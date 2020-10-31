const plainTextInput = document.getElementById("plaintext1");
const calcButton = document.getElementById("calc1");
const outputDiv = document.getElementById("output1");

const plainTextInput2 = document.getElementById("plaintext2");
const calcButton2 = document.getElementById("calc2");
const outputDiv2 = document.getElementById("output2");

const plainTextInput3 = document.getElementById("plaintext3");
const calcButton3 = document.getElementById("calc3");
const outputDiv3 = document.getElementById("output3");


const plainTextInput4 = document.getElementById("plaintext4");
const calcButton4 = document.getElementById("calc4");
const outputDiv4 = document.getElementById("output4");

const plainTextInput5 = document.getElementById("plaintext5");
const calcButton5 = document.getElementById("calc5");
const outputDiv5 = document.getElementById("output5");

const plainTextInput6 = document.getElementById("plaintext6");
const calcButton6 = document.getElementById("calc6");
const outputDiv6 = document.getElementById("output6");


// const caesarCipher = (pt) => {
//     let res = pt.toString();
//     res = "(" + res + "*&^)";
//     return res;
// }
/*
JavaScript Caesar shift

"Encrypt" like this:
    caesarShift('Attack at dawn!', 12);    // Returns "Mffmow mf pmiz!"
And "decrypt" like this:
    caesarShift('Mffmow mf pmiz!', -12);    // Returns "Attack at dawn!"
*/

var caesarShift = function (str, amount) {
    // Wrap the amount
    if (amount < 0) {
      return caesarShift(str, amount + 26);
    }
  
    // Make an output variable
    var output = "";
  
    // Go through each character
    for (var i = 0; i < str.length; i++) {
      // Get the character we'll be appending
      var c = str[i];
  
      // If it's a letter...
      if (c.match(/[a-z]/i)) {
        // Get its code
        var code = str.charCodeAt(i);
  
        // Uppercase letters
        if (code >= 65 && code <= 90) {
          c = String.fromCharCode(((code - 65 + amount) % 26) + 65);
        }
  
        // Lowercase letters
        else if (code >= 97 && code <= 122) {
          c = String.fromCharCode(((code - 97 + amount) % 26) + 97);
        }
      }
  
      // Append
      output += c;
    }
  
    // All done!
    return output;
  }

calcButton.addEventListener("click", (e) => {
    e.preventDefault();
    let output1 = "";
    let plaintext1 = plainTextInput.value;
    let encText1 = caesarShift(plaintext1,3);
    output1 += `Plain text : ${plainTextInput.value}, Encrypted text : ${encText1}`;
    outputDiv.innerText = output1;
})


///2_rot13


function rot13 (str) {
  const response = []
  const strLength = str.length

  for (let i = 0; i < strLength; i++) {
    const char = str.charCodeAt(i)

    if (char < 65 || (char > 90 && char < 97) || char > 122) {
      response.push(str.charAt(i))
    } else if ((char > 77 && char <= 90) || (char > 109 && char <= 122)) {
      response.push(String.fromCharCode(str.charCodeAt(i) - 13))
    } else {
      response.push(String.fromCharCode(str.charCodeAt(i) + 13))
    }
  }
  return response.join('')
}


calcButton2.addEventListener("click", (e) => {
  e.preventDefault();
  let output2 = "";
  let plaintext2 = plainTextInput2.value;
  let encText2 = rot13(plaintext2);
  output2 += `Plain text : ${plainTextInput2.value}, Encrypted text : ${encText2}`;
  outputDiv2.innerText = output2;
})


//RSAmod inverse

function RSA_modInvese(a, m) {
  var m0 = new SuperInteger(m);
  var x0 = new SuperInteger(0);
  var x1 = new SuperInteger(1);
  var c = new SuperInteger();
  var q = new SuperInteger();
  var t = new SuperInteger();
  
  var x0_signal = false;
  var x1_signal = false;
  var t_signal = false;
  
  if (m.eq(1)) return 0;

  while (a.greater(1)) {
      
      q = a.div(m);
      t = new SuperInteger(m);

      m = a.mod(m);
      a = new SuperInteger(t);
      
      t = new SuperInteger(x0);
      t_signal = x0_signal;
      
      c = q.times(x0);
      
      if (x1_signal == false) {
          if (x0_signal == false) {
              if (x1.greater(c)) {
                  x0 = x1.minus(c);
              } else {
                  x0_signal = true;
                  x0 = c.minus(x1);
              }
          } else {
              x0 = x1.add(c);
              x0_signal = false;
          } 
      } else {
          if (x0_signal == false) {
              x0 = x1.add(c);
              x0_signal = true;
          } else {
              if (x1.greater(c)) {
                  x0 = x1.minus(c);
              } else {
                  x0_signal = false;
                  x0 = c.minus(x1);
              }
          }
      }
      
      x1 = new SuperInteger(t);
      x1_signal = t_signal;
  }

  if (x1_signal)
     x1 = m0.minus(x1);

  return x1;
}

function RSA_generateKeys(bits) {
  var p = generatePrime(bits);
  var q = generatePrime(bits);
  var n = p.times(q);
  var phi = (p.minus(1)).times(q.minus(1));

  var tested = {};
  var e = new SuperInteger(0);
  do {
      tested[e] = 1;
      e = e.random(3, phi);
  } while (e in tested || e.gcd(phi).eq(1) == false);
  
  var d = RSA_modInvese(e, phi);
  
  return { e: e.removeZeros(), 
          d: d.removeZeros(), 
          n: n.removeZeros() };
};

function RSA_encrypt (msg, e, n) {
  if (msg == undefined) return "";
  var ciphertext = "";
  for (var i = 0; i < msg.length; i++) {
      var c = new SuperInteger(msg.charCodeAt(i)).powMod(e,n);
      var count = new SuperInteger(n);
      while (count.greater(0)) {
          var ch = c.mod(90).add(32);
          c = c.div(90);
          count = count.div(90);
          ciphertext += String.fromCharCode(ch.toString());
      }
  }
  return ciphertext;
};

function RSA_decrypt (cipher, d, n) {
  if (cipher == undefined) return "";
  var msg = "";
  var count = new SuperInteger(n);
  sum = new SuperInteger(0);
  for (var i = cipher.length-1; i >= 0; i--) {
      if (count == 0) {
          var c = sum.powMod(d,n);
          msg += String.fromCharCode(c.toString());
          count = new SuperInteger(n);
          sum = new SuperInteger(0);
      }
      sum = sum.times(90).add(cipher.charCodeAt(i)).minus(32);
      count = count.div(90);
  }
  var c = sum.powMod(d,n);
  msg += String.fromCharCode(c.toString());
  count = new SuperInteger(n);
  sum = new SuperInteger(0);
  return msg.split("").reverse().join("");;
};


calcButton3.addEventListener("click", (e) => {
  e.preventDefault();
  let output3 = "";
  let plaintext3 = plainTextInput3.value;
  let encText3 = RSA_encrypt(plaintext3,3,3);
  output3 += `Plain text : ${plainTextInput3.value}, Encrypted text : ${encText3}`;
  outputDiv3.innerText = output3;
})

//VigenereCipher



/**
 * Check if the Character is letter or not
 * @param {String} str - character to check
 * @return {object} An array with the character or null if isn't a letter
 */
function isLetter (str) {
  return str.length === 1 && str.match(/[a-zA-Z]/i)
}

/**
 * Check if is Uppercase or Lowercase
 * @param {String} character - character to check
 * @return {Boolean} result of the checking
 */
function isUpperCase (character) {
  if (character === character.toUpperCase()) {
    return true
  }
  if (character === character.toLowerCase()) {
    return false
  }
}

/**
 * Encrypt a Vigenere cipher
 * @param {String} message - string to be encrypted
 * @param {String} key - key for encrypt
 * @return {String} result - encrypted string
 */
function encrypt (message, key) {
  let result = ''

  for (let i = 0, j = 0; i < message.length; i++) {
    const c = message.charAt(i)
    if (isLetter(c)) {
      if (isUpperCase(c)) {
        result += String.fromCharCode((c.charCodeAt(0) + key.toUpperCase().charCodeAt(j) - 2 * 65) % 26 + 65) // A: 65
      } else {
        result += String.fromCharCode((c.charCodeAt(0) + key.toLowerCase().charCodeAt(j) - 2 * 97) % 26 + 97) // a: 97
      }
    } else {
      result += c
    }
    j = ++j % key.length
  }
  return result
};



calcButton4.addEventListener("click", (e) => {
  e.preventDefault();
  let output4 = "";
  let plaintext4 = plainTextInput4.value;
  let encText4 = encrypt(plaintext4,10);
  output4 += `Plain text : ${plainTextInput4.value}, Encrypted text : ${encText4}`;
  outputDiv4.innerText = output4;
})



//SHA-ALgo


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* SHA-1 (FIPS 180-4) implementation in JavaScript                    (c) Chris Veness 2002-2019  */
/*                                                                                   MIT Licence  */
/* www.movable-type.co.uk/scripts/sha1.html                                                       */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */


/**
 * SHA-1 hash function reference implementation.
 *
 * This is an annotated direct implementation of FIPS 180-4, without any optimisations. It is
 * intended to aid understanding of the algorithm rather than for production use.
 *
 * While it could be used where performance is not critical, I would recommend using the ‘Web
 * Cryptography API’ (developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest) for the browser,
 * or the ‘crypto’ library (nodejs.org/api/crypto.html#crypto_class_hash) in Node.js.
 *
 * See csrc.nist.gov/groups/ST/toolkit/secure_hashing.html
 *     csrc.nist.gov/groups/ST/toolkit/examples.html
 */
class Sha1 {

  /**
   * Generates SHA-1 hash of string.
   *
   * @param   {string} msg - (Unicode) string to be hashed.
   * @param   {Object} [options]
   * @param   {string} [options.msgFormat=string] - Message format: 'string' for JavaScript string
   *   (gets converted to UTF-8 for hashing); 'hex-bytes' for string of hex bytes ('616263' ≡ 'abc') .
   * @param   {string} [options.outFormat=hex] - Output format: 'hex' for string of contiguous
   *   hex bytes; 'hex-w' for grouping hex bytes into groups of (4 byte / 8 character) words.
   * @returns {string} Hash of msg as hex character string.
   *
   * @example
   *   import Sha1 from './sha1.js';
   *   const hash = Sha1.hash('abc'); // 'a9993e364706816aba3e25717850c26c9cd0d89d'
   */
  static hash(msg, options) {
      const defaults = { msgFormat: 'string', outFormat: 'hex' };
      const opt = Object.assign(defaults, options);

      switch (opt.msgFormat) {
          default: // default is to convert string to UTF-8, as SHA only deals with byte-streams
          case 'string':   msg = utf8Encode(msg);       break;
          case 'hex-bytes':msg = hexBytesToString(msg); break; // mostly for running tests
      }

      // constants [§4.2.1]
      const K = [ 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 ];

      // initial hash value [§5.3.1]
      const H = [ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 ];

      // PREPROCESSING [§6.1.1]

      msg += String.fromCharCode(0x80);  // add trailing '1' bit (+ 0's padding) to string [§5.1.1]

      // convert string msg into 512-bit/16-integer blocks arrays of ints [§5.2.1]
      const l = msg.length/4 + 2; // length (in 32-bit integers) of msg + ‘1’ + appended length
      const N = Math.ceil(l/16);  // number of 16-integer-blocks required to hold 'l' ints
      const M = new Array(N);

      for (let i=0; i<N; i++) {
          M[i] = new Array(16);
          for (let j=0; j<16; j++) {  // encode 4 chars per integer, big-endian encoding
              M[i][j] = (msg.charCodeAt(i*64+j*4+0)<<24) | (msg.charCodeAt(i*64+j*4+1)<<16)
                      | (msg.charCodeAt(i*64+j*4+2)<< 8) | (msg.charCodeAt(i*64+j*4+3)<< 0);
          } // note running off the end of msg is ok 'cos bitwise ops on NaN return 0
      }
      // add length (in bits) into final pair of 32-bit integers (big-endian) [§5.1.1]
      // note: most significant word would be (len-1)*8 >>> 32, but since JS converts
      // bitwise-op args to 32 bits, we need to simulate this by arithmetic operators
      M[N-1][14] = ((msg.length-1)*8) / Math.pow(2, 32); M[N-1][14] = Math.floor(M[N-1][14]);
      M[N-1][15] = ((msg.length-1)*8) & 0xffffffff;

      // HASH COMPUTATION [§6.1.2]

      for (let i=0; i<N; i++) {
          const W = new Array(80);

          // 1 - prepare message schedule 'W'
          for (let t=0;  t<16; t++) W[t] = M[i][t];
          for (let t=16; t<80; t++) W[t] = Sha1.ROTL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);

          // 2 - initialise five working variables a, b, c, d, e with previous hash value
          let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4];

          // 3 - main loop (use JavaScript '>>> 0' to emulate UInt32 variables)
          for (let t=0; t<80; t++) {
              const s = Math.floor(t/20); // seq for blocks of 'f' functions and 'K' constants
              const T = (Sha1.ROTL(a, 5) + Sha1.f(s, b, c, d) + e + K[s] + W[t]) >>> 0;
              e = d;
              d = c;
              c = Sha1.ROTL(b, 30) >>> 0;
              b = a;
              a = T;
          }

          // 4 - compute the new intermediate hash value (note 'addition modulo 2^32' – JavaScript
          // '>>> 0' coerces to unsigned UInt32 which achieves modulo 2^32 addition)
          H[0] = (H[0]+a) >>> 0;
          H[1] = (H[1]+b) >>> 0;
          H[2] = (H[2]+c) >>> 0;
          H[3] = (H[3]+d) >>> 0;
          H[4] = (H[4]+e) >>> 0;
      }

      // convert H0..H4 to hex strings (with leading zeros)
      for (let h=0; h<H.length; h++) H[h] = ('00000000'+H[h].toString(16)).slice(-8);

      // concatenate H0..H4, with separator if required
      const separator = opt.outFormat=='hex-w' ? ' ' : '';

      return H.join(separator);

      /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

      function utf8Encode(str) {
          try {
              return new TextEncoder().encode(str, 'utf-8').reduce((prev, curr) => prev + String.fromCharCode(curr), '');
          } catch (e) { // no TextEncoder available?
              return unescape(encodeURIComponent(str)); // monsur.hossa.in/2012/07/20/utf-8-in-javascript.html
          }
      }

      function hexBytesToString(hexStr) { // convert string of hex numbers to a string of chars (eg '616263' -> 'abc').
          const str = hexStr.replace(' ', ''); // allow space-separated groups
          return str=='' ? '' : str.match(/.{2}/g).map(byte => String.fromCharCode(parseInt(byte, 16))).join('');
      }
  }


  /**
   * Function 'f' [§4.1.1].
   * @private
   */
  static f(s, x, y, z)  {
      switch (s) {
          case 0: return (x & y) ^ (~x & z);          // Ch()
          case 1: return  x ^ y  ^  z;                // Parity()
          case 2: return (x & y) ^ (x & z) ^ (y & z); // Maj()
          case 3: return  x ^ y  ^  z;                // Parity()
      }
  }


  /**
   * Rotates left (circular left shift) value x by n positions [§3.2.5].
   * @private
   */
  static ROTL(x, n) {
      return (x<<n) | (x>>>(32-n));
  }

}


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

export default Sha1;



calcButton5.addEventListener("click", (e) => {
  e.preventDefault();
  let output5 = "";
  let plaintext5 = plainTextInput5.value;
  let encText5 = encrypt(plaintext5,10);
  output5 += `Plain text : ${plainTextInput5.value}, Encrypted text : ${encText5}`;
  outputDiv5.innerText = output5;
})

//DES_ALgo


var assert = require('minimalistic-assert');
var inherits = require('inherits');

var utils = require('./utils');
var Cipher = require('./cipher');

function DESState() {
  this.tmp = new Array(2);
  this.keys = null;
}

function DES(options) {
  Cipher.call(this, options);

  var state = new DESState();
  this._desState = state;

  this.deriveKeys(state, options.key);
}
inherits(DES, Cipher);
module.exports = DES;

DES.create = function create(options) {
  return new DES(options);
};

var shiftTable = [
  1, 1, 2, 2, 2, 2, 2, 2,
  1, 2, 2, 2, 2, 2, 2, 1
];

DES.prototype.deriveKeys = function deriveKeys(state, key) {
  state.keys = new Array(16 * 2);

  assert.equal(key.length, this.blockSize, 'Invalid key length');

  var kL = utils.readUInt32BE(key, 0);
  var kR = utils.readUInt32BE(key, 4);

  utils.pc1(kL, kR, state.tmp, 0);
  kL = state.tmp[0];
  kR = state.tmp[1];
  for (var i = 0; i < state.keys.length; i += 2) {
    var shift = shiftTable[i >>> 1];
    kL = utils.r28shl(kL, shift);
    kR = utils.r28shl(kR, shift);
    utils.pc2(kL, kR, state.keys, i);
  }
};

DES.prototype._update = function _update(inp, inOff, out, outOff) {
  var state = this._desState;

  var l = utils.readUInt32BE(inp, inOff);
  var r = utils.readUInt32BE(inp, inOff + 4);

  // Initial Permutation
  utils.ip(l, r, state.tmp, 0);
  l = state.tmp[0];
  r = state.tmp[1];

  if (this.type === 'encrypt')
    this._encrypt(state, l, r, state.tmp, 0);
  else
    this._decrypt(state, l, r, state.tmp, 0);

  l = state.tmp[0];
  r = state.tmp[1];

  utils.writeUInt32BE(out, l, outOff);
  utils.writeUInt32BE(out, r, outOff + 4);
};

DES.prototype._pad = function _pad(buffer, off) {
  var value = buffer.length - off;
  for (var i = off; i < buffer.length; i++)
    buffer[i] = value;

  return true;
};

DES.prototype._unpad = function _unpad(buffer) {
  var pad = buffer[buffer.length - 1];
  for (var i = buffer.length - pad; i < buffer.length; i++)
    assert.equal(buffer[i], pad);

  return buffer.slice(0, buffer.length - pad);
};

DES.prototype._encrypt = function _encrypt(state, lStart, rStart, out, off) {
  var l = lStart;
  var r = rStart;

  // Apply f() x16 times
  for (var i = 0; i < state.keys.length; i += 2) {
    var keyL = state.keys[i];
    var keyR = state.keys[i + 1];

    // f(r, k)
    utils.expand(r, state.tmp, 0);

    keyL ^= state.tmp[0];
    keyR ^= state.tmp[1];
    var s = utils.substitute(keyL, keyR);
    var f = utils.permute(s);

    var t = r;
    r = (l ^ f) >>> 0;
    l = t;
  }

  // Reverse Initial Permutation
  utils.rip(r, l, out, off);
};

DES.prototype._decrypt = function _decrypt(state, lStart, rStart, out, off) {
  var l = rStart;
  var r = lStart;

  // Apply f() x16 times
  for (var i = state.keys.length - 2; i >= 0; i -= 2) {
    var keyL = state.keys[i];
    var keyR = state.keys[i + 1];

    // f(r, k)
    utils.expand(l, state.tmp, 0);

    keyL ^= state.tmp[0];
    keyR ^= state.tmp[1];
    var s = utils.substitute(keyL, keyR);
    var f = utils.permute(s);

    var t = l;
    l = (r ^ f) >>> 0;
    r = t;
  }

  // Reverse Initial Permutation
  utils.rip(l, r, out, off);
};


calcButton6.addEventListener("click", (e) => {
  e.preventDefault();
  let output6 = "";
  let plaintext6 = plainTextInput6.value;
  let encText6 = _encrypt(plaintext6,5,5,off);
  output6 += `Plain text : ${plainTextInput6.value}, Encrypted text : ${encText6}`;
  outputDiv6.innerText = output6;
})



