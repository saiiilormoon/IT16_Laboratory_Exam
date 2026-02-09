function combineText() {
    const name = document.getElementById("fullName").value.toUpperCase();
    const year = document.getElementById("year").value;
    const course = document.getElementById("course").value.toUpperCase();

    return `${name} | ${year} | ${course}`;
}

function caesarCipher(text, shift) {
    let result = "";

    for (let i = 0; i < text.length; i++) {
        let char = text[i];

        if (char >= 'A' && char <= 'Z') {
            let code = text.charCodeAt(i) - 65;
            let shifted = (code + shift + 26) % 26;
            result += String.fromCharCode(shifted + 65);
        } else {
            result += char; // symbols, numbers, spaces unchanged
        }
    }
    return result;
}

function encrypt() {
    const key = parseInt(document.getElementById("key").value);
    if (isNaN(key) || key < 1 || key > 25) {
        alert("Key must be between 1 and 25");
        return;
    }

    const plain = combineText();
    document.getElementById("plaintext").value = plain;
    document.getElementById("result").value = caesarCipher(plain, key);
}

function decrypt() {
    const key = parseInt(document.getElementById("key").value);
    if (isNaN(key) || key < 1 || key > 25) {
        alert("Key must be between 1 and 25");
        return;
    }

    const cipherText = document.getElementById("result").value;
    document.getElementById("plaintext").value = caesarCipher(cipherText, -key);
}

function clearAll() {
    document.querySelectorAll("input, textarea").forEach(el => el.value = "");
}
