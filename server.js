const express = require('express');
const axios = require('axios');
const cors = require('cors');
const whois = require('whois-json');
const multer = require('multer');
const FormData = require('form-data');
const https = require('https');
const app = express();
app.use(express.json());
app.use(cors());

const upload = multer({ dest: 'uploads/' });

app.post('/analyze', async (req, res) => {
    const { url } = req.body;
    let risk = 'Safe';
    let details = '';
    let confidence = 0;

    
    const suspiciousTlds = ['.xyz', '.top', '.club'];
    const tld = url.split('.').pop();
    if (suspiciousTlds.includes('.' + tld)) {
        risk = 'Suspicious';
        details += 'Suspicious TLD detected. ';
        confidence += 20;
    }

   
    try {
        const sslResponse = await axios.get(url, { httpsAgent: new https.Agent({ rejectUnauthorized: false }) });
        if (!url.startsWith('https://')) {
            risk = 'Suspicious';
            details += 'No SSL certificate (not HTTPS). ';
            confidence += 15;
        } else {
            details += 'SSL certificate valid. ';
        }
    } catch (error) {
        risk = 'Suspicious';
        details += 'SSL check failed. ';
    }

   
    try {
        const ipinfoKey = 'b972903db6aa9d'; //  ipinfo.io key
        const domain = new URL(url).hostname;
        const ipResponse = await axios.get(`https://ipinfo.io/${domain}?token=${ipinfoKey}`);
        const country = ipResponse.data.country;
        details += `Server location: ${country}. `;
        if (['CN', 'RU', 'IR'].includes(country)) { 
            risk = 'Suspicious';
            details += 'Suspicious server location. ';
            confidence += 10;
        }
    } catch (error) {
        details += 'Geolocation unavailable. ';
    }


    try {
        const domain = new URL(url).hostname;
        const whoisData = await whois(domain);
        const creationDate = new Date(whoisData.creationDate);
        const ageInDays = Math.floor((Date.now() - creationDate.getTime()) / (1000 * 60 * 60 * 24));
        if (ageInDays < 30) {
            risk = 'Suspicious';
            details += `Domain is only ${ageInDays} days old. `;
            confidence += 25;
        } else {
            details += `Domain age: ${ageInDays} days. `;
        }
    } catch (error) {
        details += 'Could not check domain age. ';
    }

  
    try {
        const reachabilityResponse = await axios.get(url, { timeout: 5000 });
        if (reachabilityResponse.status !== 200) {
            risk = 'Suspicious';
            details += 'URL is not reachable or returns error. ';
            confidence += 10;
        } else {
            details += 'URL is reachable. ';
        }
    } catch (error) {
        risk = 'Suspicious';
        details += 'URL is not reachable. ';
        confidence += 10;
    }

   
    try {
        const apiKey = 'AIzaSyC5YI7K_pFf7xF6WbbnLz0ZYmuvq0dPS78'; // google key
        const response = await axios.post(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
            client: { clientId: 'cryvora', clientVersion: '1.0' },
            threatInfo: { threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING'], platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: [{ url }] }
        });
        if (response.data.matches) {
            risk = 'Malicious';
            details += 'Flagged by Google Safe Browsing. ';
            confidence += 40;
        } else {
            details += 'API check passed. ';
        }
    } catch (error) {
        details += 'API check failed. ';
    }

  
    try {
        const vtApiKey = '8bfe5116c082daf15d5d50010c2eda69436e246762e5f327a08f135ede3ce376'; // vtapi key
        const vtResponse = await axios.post(`https://www.virustotal.com/api/v3/urls`, `url=${encodeURIComponent(url)}`, {
            headers: {
                'x-apikey': vtApiKey,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });
        const scanId = vtResponse.data.data.id;
        
        setTimeout(async () => {
            try {
                const resultResponse = await axios.get(`https://www.virustotal.com/api/v3/analyses/${scanId}`, {
                    headers: { 'x-apikey': vtApiKey }
                });
                const positives = resultResponse.data.data.attributes.stats.malicious;
                if (positives > 0) {
                    risk = 'Malicious';
                    details += `VirusTotal flagged ${positives} engines as malicious. `;
                    confidence += 30;
                } else {
                    details += 'VirusTotal scan clean. ';
                }
            } catch (innerError) {
                details += 'VirusTotal scan unavailable. ';
            }
        }, 10000);
    } catch (error) {
        details += 'VirusTotal scan unavailable. ';
    }


    if (confidence > 50) risk = 'Malicious';
    else if (confidence > 20) risk = 'Suspicious';

    res.json({ risk, details, confidence });
});


app.post('/analyze-image', upload.single('image'), async (req, res) => {
    if (!req.file) return res.status(400).json({ risk: 'Error', details: 'No image uploaded.' });

    let risk = 'Safe';
    let details = 'Image analyzed. ';
    let confidence = 0;

   
    try {
        const ocrApiKey = 'K88616555888957'; //  OCR.space key
        const form = new FormData();
        form.append('file', require('fs').createReadStream(req.file.path));
        form.append('language', 'eng');
        form.append('isOverlayRequired', 'false');

        const ocrResponse = await axios.post('https://api.ocr.space/parse/image', form, {
            headers: {
                ...form.getHeaders(),
                'apikey': ocrApiKey
            }
        });

        const text = ocrResponse.data.ParsedResults[0].ParsedText;
        details += `Extracted text: ${text.substring(0, 100)}... `;

        // Simple keyword check for scams
        const scamKeywords = ['urgent', 'win prize', 'free money', 'click here', 'password required'];
        const foundKeywords = scamKeywords.filter(keyword => text.toLowerCase().includes(keyword));
        if (foundKeywords.length > 0) {
            risk = 'Suspicious';
            details += `Suspicious keywords found: ${foundKeywords.join(', ')}. `;
            confidence += 40;
        } else {
            details += 'No suspicious keywords detected. ';
        }
    } catch (error) {
        details += 'OCR scan failed. ';
    }

    res.json({ risk, details, confidence });
});


app.post('/ai-analyze', async (req, res) => {
    const { input, platform } = req.body;
    let analysis = 'Safe';
    let action = 'No action taken';

    try {
        
        const hfApiKey = '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'; //  Hugging Face key
        const hfResponse = await axios.post('https://api-inference.huggingface.co/models/microsoft/DialoGPT-medium', {
            inputs: `Classify this ${platform} for threats: ${input}`
        }, {
            headers: { 'Authorization': `Bearer ${hfApiKey}` }
        });

        // Simple logic: If response indicates threat, flag it
        const aiOutput = hfResponse.data[0]?.generated_text || '';
        if (aiOutput.toLowerCase().includes('threat') || aiOutput.toLowerCase().includes('phishing')) {
            analysis = 'Threat Detected';
            action = `Auto-blocked on ${platform}`;
        } else {
            analysis = 'Safe';
            action = 'Allowed';
        }

    } catch (error) {
        analysis = 'Analysis failed';
        action = 'Manual check recommended';
    }

    res.json({ analysis, action });
});

app.listen(3000, () => console.log('Cryvora server running on port 3000'));