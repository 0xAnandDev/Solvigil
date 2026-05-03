const fs = require('fs');
const https = require('https');
const http = require('http');

// Test 1: Health Check
console.log('TEST 1: Health Check');
http.get('http://localhost:5000/api/health', (res) => {
    let data = '';
    res.on('data', chunk => data += chunk);
    res.on('end', () => console.log('✓ Health:', JSON.parse(data)));
}).on('error', (e) => console.log('✗ Error:', e.message));

// Test 2: Empty File
setTimeout(() => {
    console.log('\nTEST 2: Empty File (should error)');
    fs.writeFileSync('empty.sol', '');
    testUpload('empty.sol');
}, 1000);

// Test 3: Valid Contract
setTimeout(() => {
    console.log('\nTEST 3: Valid Contract with Vulnerability');
    const code = `pragma solidity ^0.6.0;
contract Test {
  mapping(address => uint) public balance;
  function withdraw(uint amount) public {
    (bool success, ) = msg.sender.call{value: amount}("");
    balance[msg.sender] -= amount;
  }
}`;
    fs.writeFileSync('vulnerable.sol', code);
    testUpload('vulnerable.sol');
}, 2000);

// Test 4: Wrong File Type
setTimeout(() => {
    console.log('\nTEST 4: Wrong File Type (should error)');
    fs.writeFileSync('wrong.txt', 'not solidity');
    testUpload('wrong.txt');
}, 3000);

// Test 5: Safe Contract
setTimeout(() => {
    console.log('\nTEST 5: Safe Contract');
    const code = `pragma solidity ^0.8.0;
contract Safe {
  uint public counter = 0;
  function increment() public {
    counter++;
  }
}`;
    fs.writeFileSync('safe.sol', code);
    testUpload('safe.sol');
}, 4000);

function testUpload(filename) {
    const file = fs.readFileSync(filename);
    const boundary = '----FormBoundary' + Math.random().toString(36).substr(2);

    const body = `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`;
    const footer = `\r\n--${boundary}--`;

    const requestBody = Buffer.concat([
        Buffer.from(body),
        file,
        Buffer.from(footer)
    ]);

    const options = {
        hostname: 'localhost',
        port: 5000,
        path: '/api/analyze',
        method: 'POST',
        headers: {
            'Content-Type': `multipart/form-data; boundary=${boundary}`,
            'Content-Length': requestBody.length
        }
    };

    const req = http.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
            try {
                const json = JSON.parse(data);
                console.log(`✓ ${filename}:`, json.analysis ? `Score: ${json.analysis.securityScore}` : json.error);
            } catch {
                console.log(`✓ ${filename}:`, data);
            }
        });
    }).on('error', (e) => console.log(`✗ ${filename}:`, e.message));

    req.write(requestBody);
    req.end();
}