const { Resolver } = require('node:dns');
const express = require('express');
const path = require('path');
const ipRangeCheck = require('ip-range-check');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));

const resolver = new Resolver();
resolver.setServers(['1.1.1.1']);

// Create a separate resolver for recursive lookups
const recursiveResolver = new Resolver();
recursiveResolver.setServers(['1.1.1.1', '8.8.8.8']);

// Function to parse SPF record components
function parseSpfRecord(recordStr) {
    const ipv4Matches = recordStr.match(/ip4:([^\s]+)/g) || [];
    const includeMatches = recordStr.match(/include:([^\s]+)/g) || [];
    
    return { 
        ipv4: ipv4Matches.map(ip => ip.replace('ip4:', '')),
        includes: includeMatches.map(inc => inc.replace('include:', ''))
    };
}

// Recursive function to lookup SPF records and build tree structure
async function lookupSpfRecords(domain, depth = 0, maxDepth = 10, visited = new Set()) {
    if (depth > maxDepth || visited.has(domain)) {
        return {
            domain,
            error: depth > maxDepth ? 'Max depth reached' : 'Circular reference detected',
            ipRanges: [],
            children: [],
            spfRecord: null
        };
    }
    
    visited.add(domain);
    
    return new Promise((resolve) => {
        recursiveResolver.resolveTxt(domain, async (err, records) => {
            const result = {
                domain,
                ipRanges: [],
                children: [],
                error: null,
                spfRecord: null
            };
            
            if (err) {
                result.error = err.message;
                resolve(result);
                return;
            }
            
            for (const record of records) {
                const recordStr = record.toString();
                if (recordStr.includes('v=spf1')) {
                    const { ipv4, includes } = parseSpfRecord(recordStr);
                    
                    // Add IP ranges and SPF record text to result
                    result.ipRanges = ipv4;
                    result.spfRecord = recordStr;
                    
                    // Recursively lookup included domains
                    for (const includeDomain of includes) {
                        const childResult = await lookupSpfRecords(
                            includeDomain, 
                            depth + 1, 
                            maxDepth, 
                            new Set(visited)
                        );
                        result.children.push(childResult);
                    }
                    break; // Only process the first SPF record found
                }
            }
            
            resolve(result);
        });
    });
}

// Function to collect all IP ranges from a tree structure
function collectAllIpRanges(tree, ranges = []) {
    if (tree.ipRanges && tree.ipRanges.length > 0) {
        ranges.push(...tree.ipRanges.map(range => ({
            range,
            domain: tree.domain
        })));
    }
    
    if (tree.children) {
        tree.children.forEach(child => collectAllIpRanges(child, ranges));
    }
    
    return ranges;
}

// Function to check if an IP is in any of the ranges
function checkIpInRanges(ip, ranges) {
    const matches = [];
    
    for (const { range, domain } of ranges) {
        try {
            if (ipRangeCheck(ip, range)) {
                matches.push({ range, domain });
            }
        } catch (error) {
            // Skip invalid ranges
            console.warn(`Invalid range ${range}:`, error.message);
        }
    }
    
    return matches;
}

// API Routes
app.get('/api/spf/:domain', async (req, res) => {
    try {
        const domain = req.params.domain;
        
        // Validate domain format
        if (!domain || !/^[a-zA-Z0-9.-]+$/.test(domain)) {
            return res.status(400).json({ error: 'Invalid domain format' });
        }
        
        const spfTree = await lookupSpfRecords(domain);
        res.json(spfTree);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/check-ip', async (req, res) => {
    try {
        const { ip, domain } = req.body;
        
        if (!ip || !domain) {
            return res.status(400).json({ error: 'IP and domain are required' });
        }
        
        // Validate IP format
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (!ipRegex.test(ip)) {
            return res.status(400).json({ error: 'Invalid IP address format' });
        }
        
        // Get SPF records for the domain
        const spfTree = await lookupSpfRecords(domain);
        const allRanges = collectAllIpRanges(spfTree);
        const matches = checkIpInRanges(ip, allRanges);
        
        res.json({
            ip,
            domain,
            matches,
            isAuthorized: matches.length > 0
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Serve the main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`DNS SPF Lookup Tool running on http://localhost:${PORT}`);
});