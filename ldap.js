const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const ldap = require('ldapjs');
require('dotenv').config();
const app = express();

app.use(bodyParser.json());
app.use(cors());

app.post('/api/authenticate', async (req, res) => {
    const { email, password } = req.body;

    try {
        const isAuthenticated = await authenticate(email, password);
        res.json({ isAuthenticated });
    } catch(error) {
        console.error('Error in authentication:', error);
        res.status(500).json({ error: 'internal server error' });
    }
});

function authenticate(email, password) {
    return new Promise((resolve, reject) => {
        const server = ldap.createClient({ url: process.env.LDAP_URL, reconnect: false });
        server.bind(process.env.LDAP_USER_DN, process.env.LDAP_PASSWORD, (err) => {
            if(err) {
                console.error('LDAP bind error:', err);
                resolve(false);
            }

            const filterStr = `(&(objectClass=user)(userPrincipalName=${email}))`;
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
}

function fixName(name) {
    // workaround to fix a problem with LDAPJS
    return decodeURI(name.replaceAll("\\", "%"));
}

const port = 3001;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

