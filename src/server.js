// server.js

// --- MODULE IMPORTS ---
// Standard imports for core Node.js functionality and Express framework
const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const multer = require('multer');


// --- PKI/SSL Configuration ---

const KEYS_PATH = path.join(__dirname, '..', '..', 'infra', 'openssl');
const UPLOAD_PATH = path.join(__dirname, '..', '..', 'uploads'); 
let sslOptions;

// Load the keys and certificates with error checking
try {
    const serverKey = fs.readFileSync(path.join(KEYS_PATH, 'server-key.pem'));
    const serverCert = fs.readFileSync(path.join(KEYS_PATH, 'server-cert.pem'));
    const caCert = fs.readFileSync(path.join(KEYS_PATH, 'ca-cert.pem')); 

    sslOptions = {
        key: serverKey,
        cert: serverCert,
        requestCert: true,     // REQUIRE client certificate
        rejectUnauthorized: true, // REJECT connection if client cert is invalid
        ca: caCert,            // CA used to verify client certificates
    };

} catch (error) {
    // This catches file not found errors from the PKI setup
    console.error("❌ PKI FILE ERROR: Failed to read essential PKI files.");
    console.error("Ensure all files (server-key.pem, server-cert.pem, ca-cert.pem) exist in:", KEYS_PATH);
    console.error("Details:", error.message);
    process.exit(1);
}

// Ensure the upload directory exists
if (!fs.existsSync(UPLOAD_PATH)) {
    fs.mkdirSync(UPLOAD_PATH);
    console.log(`Created directory: ${UPLOAD_PATH}`);
}

// Multer storage configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, UPLOAD_PATH); },
    filename: (req, file, cb) => { cb(null, `${Date.now()}-${file.originalname}`); }
});

const upload = multer({ storage: storage });
const app = express();

// --- Middleware ---

app.use(express.json());

// Basic CORS headers to allow browser access from file:// or other origins
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*'); 
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS'); // Added DELETE
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    next();
});

// --- CORE APPLICATION ROUTES ---

// 1. UPLOAD ROUTE (POST)
app.post('/upload', upload.single('secureFile'), (req, res) => {
    if (!req.file) return res.status(400).send('No file uploaded.');
    
    const clientCert = req.socket.getPeerCertificate();
    if (clientCert && clientCert.subject) {
        const clientIdentifier = clientCert.subject.CN || 'Unknown Client';
        console.log(`[UPLOAD] File uploaded by secure client. CN: ${clientIdentifier}`);
        res.status(200).json({ 
            message: 'File uploaded securely!', 
            filename: req.file.filename,
            clientCN: clientIdentifier
        });
    } else {
        res.status(401).send('Unauthorized access (mTLS handshake failed).');
    }
});

// 2. LIST FILES ROUTE (GET)
app.get('/files', (req, res) => {
    const clientCert = req.socket.getPeerCertificate();
    if (!clientCert || !clientCert.subject) {
        return res.status(401).send('Unauthorized. mTLS client identity required to list files.');
    }
    
    try {
        const files = fs.readdirSync(UPLOAD_PATH);
        console.log(`[LIST] Client ${clientCert.subject.CN} listed ${files.length} files.`);
        res.status(200).json(files);
    } catch (error) {
        console.error('Error reading upload directory:', error);
        res.status(500).json({ error: 'Failed to read upload directory.' });
    }
});

// 3. DOWNLOAD ROUTE (GET)
app.get('/download/:filename', (req, res) => {
    const filename = req.params.filename;
    // Security measure against directory traversal attacks
    if (filename.includes('..')) {
        return res.status(400).send('Invalid filename provided.');
    }

    const filePath = path.join(UPLOAD_PATH, filename);
    const clientCert = req.socket.getPeerCertificate();
    
    if (clientCert && clientCert.subject) {
        if (fs.existsSync(filePath)) {
            console.log(`[DOWNLOAD] Client ${clientCert.subject.CN} downloading file: ${filename}`);
            res.download(filePath, filename, (err) => {
                if (err && !res.headersSent) res.status(500).send('Could not complete the download.');
            });
        } else {
            res.status(404).send('File not found.');
        }
    } else {
        res.status(401).send('Unauthorized. mTLS client identity required.');
    }
});

// 4. DELETE ROUTE (DELETE)
app.delete('/files/:filename', (req, res) => {
    const filename = req.params.filename;
    // Security measure against directory traversal attacks
    if (filename.includes('..')) {
        return res.status(400).json({ error: 'Invalid filename provided.' });
    }
    
    const filePath = path.join(UPLOAD_PATH, filename);
    const clientCert = req.socket.getPeerCertificate();

    if (!clientCert || !clientCert.subject) {
        return res.status(401).send('Unauthorized. mTLS client identity required for deletion.');
    }

    if (fs.existsSync(filePath)) {
        try {
            fs.unlinkSync(filePath); // Delete the file from the disk
            console.log(`[DELETE] Client ${clientCert.subject.CN} deleted file: ${filename}`);
            res.status(200).json({ message: `File ${filename} deleted successfully.` });
        } catch (error) {
            console.error('Error deleting file:', error);
            res.status(500).json({ error: 'Failed to delete file from disk. Check server permissions.' });
        }
    } else {
        res.status(404).json({ error: 'File not found.' });
    }
});

// 5. ROOT HEALTH CHECK (GET)
app.get('/', (req, res) => {
    const clientCert = req.socket.getPeerCertificate();
    let message = 'Secure Server is running successfully.';
    if (clientCert && clientCert.subject) {
        message += ` You are authenticated via mTLS as: ${clientCert.subject.CN}`;
    }
    res.send(`<h1>${message}</h1><p>Endpoints: /upload, /download, /files, /delete</p>`);
});


// --- Server Start ---
const PORT = 3000;
https.createServer(sslOptions, app).listen(PORT, () => {
    console.log(`✅ Secure server running on https://localhost:${PORT}`);
    console.log('🔒 PKI Integration Enabled (Mutual TLS).');
});
