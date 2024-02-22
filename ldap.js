const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const ldap = require('ldapjs');
require('dotenv').config();
const {verifyToken, createToken} = require("./verifyToken.js");

const adminEmails = ['s.savasta@asc.de', 'm.komm@asc.de', 'r.roesel@asc.de', 'p.schmitt@asc.de', 'j.fountain@asc.de'];

const app = express();

app.use(bodyParser.json());
app.use(cors());

app.post('/api/authenticate', async (req, res) => {
    const { email, password } = req.body;

    try {
        const isAuthenticated = await authenticate(email, password);
        if (isAuthenticated) {
            const token = createToken(email);
            const isAdmin = adminEmails.includes(email);
            res.json({ isAuthenticated, token, isAdmin });
        } else {
            res.json({ isAuthenticated });
        }
    } catch(error) {
        console.error('Error in authentication:', error);
        res.status(500).json({ error: 'internal server error' });
    }
});

app.get('/api/token', verifyToken, async (req, res) => {
    res.json({ token: req.headers['authorization'] });
});

app.get('/api/checkadminstatus', verifyToken, (req, res) => {
    const email = req.decoded.username;
    const isAdmin = adminEmails.includes(email);
res.json({ isAdmin });
});

function authenticate(email, password) {
    try{
        const server = ldap.createClient({ url: process.env.LDAP_URL, reconnect: false });
        server.on('error', (error) => {
            console.warn(new Date(), "Error in authenticate:", error);
        });
        return new Promise((resolve, reject) => {
            server.bind(process.env.LDAP_USER_DN, process.env.LDAP_PASSWORD, (err) => {
                if(err) {
                    console.error('LDAP bind error:', err);
                    resolve(false);
                }
                
                const filterStr = `(&(objectClass=user)(|(userPrincipalName=${email})(email=${email}))`;
                const searchOptions = {
                    filter: filterStr,
                    scope: 'sub'
                };
    
                server.search(process.env.LDAP_SEARCH_BASE, searchOptions, (searchErr, searchRes) => {
                    if(searchErr) {
                        console.error('LDAP search error:', searchErr);
                        resolve(false);
                    }
    
                    let foundEntry = false;
                    searchRes.on('searchEntry', (entry) => {
                        foundEntry = true;
                        const dn = entry.dn;
                        const userServer = ldap.createClient({ url: process.env.LDAP_URL});
                        const dnString = fixName(dn.toString());
    
                        userServer.bind(dnString, password, (bindErr) => {
                            try {
                                if(bindErr) {
                                    console.log('LDAP bind error:', bindErr);
                                    resolve(false);
                                    return;
                                }
    
                                console.log('User authenticated');
                                resolve(true);
                            } catch(error) {
                                console.error('Error in authentication:', error);
                                resolve(false);
                            } finally {
                                userServer.destroy();
                            }
                        });
                    });
    
                    searchRes.on('end', () => {
                        if(!foundEntry) {
                            console.log('User not found');
                            resolve(false);
                        }
                    });
                });
            });
        });
    } catch (error) {
        console.error(error);
        return false;
    } 
}

function fixName(name) {
    // workaround to fix a problem with LDAPJS
    return decodeURI(name.replaceAll("\\", "%"));
}

const port = 3001;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
