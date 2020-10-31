/**
 * Cipher functions that are available
 * Caesar Cipher
 * Vignere Cipher
 */


 /**
 * Declaring all the buttons, inputs etc used in the project here
 */
const plaintextInput = document.getElementById("plaintext");
const calculateButton = document.getElementById("calculate");
const outputDiv = document.getElementById("output");
const selector = document.getElementById("ciphers");

/**
 * Function for calculating caesar cipher encryption
 */
const caesarShift = function (str, amount) {
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

/**
 * Vignere Cipher Algorithm
 */

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
const vignereEncrypt = (message, key) => {
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
}

/**
 * Decrypt a Vigenere cipher
 * @param {String} message - string to be decrypted
 * @param {String} key - key for decrypt
 * @return {String} result - decrypted string
 */
const vignereDecrypt = (message, key) => {
  let result = ''

  for (let i = 0, j = 0; i < message.length; i++) {
    const c = message.charAt(i)
    if (isLetter(c)) {
      if (isUpperCase(c)) {
        result += String.fromCharCode(90 - (25 - (c.charCodeAt(0) - key.toUpperCase().charCodeAt(j))) % 26)
      } else {
        result += String.fromCharCode(122 - (25 - (c.charCodeAt(0) - key.toLowerCase().charCodeAt(j))) % 26)
      }
    } else {
      result += c
    }
    j = ++j % key.length
  }
  return result
}




/**
 * Adding all the functions on the click listener
 * to the button
 */
calculateButton.addEventListener("click", e => {
  e.preventDefault();   // To prevent the default behaviour of submitting the form
  const selectedCipher = selector.value;
  const plaintext = plaintextInput.value;
  let encryptedText = '', output = '';

  switch (selectedCipher) {
    case 'caesar':
      encryptedText = caesarShift(plaintext, 3); // Provide the shift as second argument
      output = `Plaintext : ${plaintext}, Ciphertext : ${encryptedText}`;
      break;
    case 'vignere':
      encryptedText = vignereEncrypt(plaintext, 'nimisha'); // Provide the key as second argument
      output = `Plaintext : ${plaintext}, Ciphertext : ${encryptedText}`;
      break;
    default:
      output = `Please select a valid encryption algorithm :)`;
  }
  outputDiv.innerText = output;
});