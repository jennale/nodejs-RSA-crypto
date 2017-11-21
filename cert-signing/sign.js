/**
 * Jenna Le
 *
 *  
 * This file uses a params.json file (or another specified) to retrieve the n, d, 
 * and public exponent
 * 
 * Crypto library info: https://nodejs.org/api/crypto.html
 * 
 * To run this file (with NodeJS installed): 
 * > node sign.js --file=x(optional) --paramsFile=y(optional)
 * 
 */
const fs = require('mz/fs');
const util = require('util');
const crypto = require('crypto');
const args = require('yargs').argv;
const bigInt = require('big-integer');
const ASN1_SHA256_HEADER = '3031300d060960864801650304020105000420'; //This is always the same

util.promisify(fs.readFile);

let n, //modulus, or public Key
  e, //exponent
  d, //d
  fileName,
  messageBuffer; //message, as a buffer read directly from the file.

/**
 * Padding function that replicates PKCS#1. (Because this function could not be separated from NodeJS crypto, a basic version was recreated here)
 * @param {string} hexValueToPad 
 * @param {bigInt} maxValueInt 
 */
pad = (hexValueToPad, maxValueInt) => {
  let padding = '0001', //Padding begins with a 1
    fffs = 'f', //Padded with a series of f's
    newResult = bigInt();

  //Padding only continues until it is less than the size of the modulo (maxValueInt)
  while (!newResult.greater(maxValueInt)) {
    result = newResult;
    //Create a new big integer with the padding, ASN.1 header, and sha hex value;
    newResult = bigInt(
      padding + fffs + '00' + ASN1_SHA256_HEADER + hexValueToPad,
      16
    );
    fffs += 'f';
  }

  //Result returned is BigInt type
  return result;
};

/**
 * Reads from the files (optionally added via command line) and sets the global objects
 * Usage: node sign.js --file=x --paramsFile=y
 * @param {string} file 
 * @param {string} paramsFile 
 */
readFiles = async (file = './sign.js', paramsFile = './params.json') => {
  let content;

  try {
    content = await fs.readFile(paramsFile, 'utf8');
  } catch (e) {
    console.error('error! check if params.json exists');
    process.exit(1);
  }

  let json = JSON.parse(content);
  n = bigInt(json.n);
  e = parseInt(json.e);
  d = bigInt(json.d);

  try {
    messageBuffer = await fs.readFile(file);
  } catch (e) {
    console.error('error in reading file');
    console.error(e);
    process.exit(1);
  }
};

/**
 * The main function. Reads from files, and signs + prints a file into the console.
 */
main = async () => {
  //Get input parameters if set.
  let fileName = args.file || './sign.js'; //Default is this current file
  let paramFileName = args.paramsFile || './params.json'; //Default is the params.json file
  await readFiles(fileName, paramFileName);

  //Hash the message buffer using SHA-256
  const hash = crypto.createHash('sha256');
  let messageHash = hash.update(messageBuffer).digest('hex');

  //Pad the message using the simple PKCS#1 padder. Value returned by pad() is a BigInt
  let hashedPaddedMessage = pad(messageHash, n);

  //Use the private key d to 'encrypt' the message.
  let signed = hashedPaddedMessage.modPow(d, n);

  //Print to console in HEX
  console.log(signed.toString(16));

  //debug flags
  if (args.showMsg) {
    console.log('\nhashed+padded msg:\n' + hashedPaddedMessage.toString(16));
  }
  if (args.verify) {
    let verify = signed.modPow(e, n);
    console.log('\nverified msg:\n' + verify.toString(16));
  }

  //Uncomment below to debug and visually verify the messages match and compare with openSHA results
  // console.log(messageHash);
  // console.log(hashedPaddedMessage.toString(16));
  // console.log(signed.toString(16));
};

//Run the main function
main();
