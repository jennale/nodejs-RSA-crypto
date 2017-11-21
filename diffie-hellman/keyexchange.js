/**
 * Jenna Le
 *  
 * This file uses a params.json file (or another specified) to retrieve the 
 * p, g, and public key. Uses diffie-hellman
 * 
 * The secret key is hardcoded 
 * To run this file (with NodeJS installed): 
 * > node keyexchange.js 
 * 
 */
const fs = require('fs');
const bigInt = require('big-integer'); //Uses the bigInt library for modpow calculations

let sharedSecret,
  p, //input param (from file) 32745481...
  g, //input param (from file) 3
  serverPublic, //input param (from file) 27077741214992948...
  clientPublic,
  serverPrivate,
  clientPrivate = bigInt(123456789); //hardcoded

fs.readFile('./params.json', 'utf8', (err, content) => {
  if (err) {
    console.error('error! check if params.json exists');
    process.exit(1);
  }

  //Read from params.json and set the global variables
  let json = JSON.parse(content);
  p = bigInt(json.p);
  g = bigInt(json.g);
  serverPublic = bigInt(json.y_s);

  //Create the client public key, which is (g^clientPrivate)mod(p)
  let clientPublic = g.modPow(clientPrivate, p);

  //Create the shared secret, which is (serverPublic^clientPrivate)mod(p)
  let sharedSecret = serverPublic.modPow(clientPrivate, p);

  console.log(`client public:
${clientPublic.toString()}

shared secret: 
${sharedSecret.toString()}`);
});
