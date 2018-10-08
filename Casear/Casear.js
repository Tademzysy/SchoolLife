window.onload = init;

function init() {
    var plaintextInput = document.getElementById("plaintextInput"); //明文输入文本框
    var keyInput = document.getElementById("keyInput");   //明文密钥输入框
    var buttonOne = document.getElementById("buttonOne");  //加密按钮
    var messageArea = document.getElementById("MessageArea");  //密文显示
    var ciphertextInput = document.getElementById("ciphertextInput"); //密文输入文本框
    var key_oneInput = document.getElementById("key_oneInput");  //解密密钥
    var buttonTwo = document.getElementById("buttonTwo");  //解密按钮
    var messageAreaTwo = document.getElementById("MessageAreaTwo");

    buttonOne.onclick = function () {
        var plaintext = plaintextInput.value;
        var key = Number(keyInput.value) % 26;
        var ciphertext = "";
        for (var i = 0; i < plaintext.length; i++) {
            var num = plaintext[i].charCodeAt();  //单个字符对应的ASC码
            var charCode = plaintext[i].charCodeAt() + key;
            charCode = correctCharCode(num, charCode);
            var result_char = String.fromCharCode(charCode);
            ciphertext += result_char;

        }

        messageArea.innerHTML = ciphertext;

    }   //加密

    buttonTwo.onclick = function () {
        var ciphertext = ciphertextInput.value;
        var key_one = Number(key_oneInput.value) % 26;
        var plaintext = "";
        for (var i = 0; i < ciphertext.length; i++) {
            var num = ciphertext[i].charCodeAt();
            var charCode = ciphertext[i].charCodeAt() - key_one;
            charCode = correctCharCode(num, charCode);
            var result_char = String.fromCharCode(charCode);
            plaintext += result_char;

        }

        messageAreaTwo.innerHTML = plaintext;

    }  //解密


    ciphertextInput.onkeypress = function (enter) {
        if (enter.keyCode === 13) {
            ciphertextInput.value = messageArea.innerHTML;
        }

    }
    //使用回车键便捷输入需要解密的密文

    key_oneInput.onkeypress = function (enter) {
        if (enter.keyCode === 13) {
            key_oneInput.value = keyInput.value;
        }

        setTimeout(buttonTwo.click(), 1000);
    }
       //使用回车键快便捷输入解密密钥

    keyInput.onkeypress = function (enter) {
        if (enter.keyCode === 13){
            buttonOne.click();
        }
    }
      //使用回车进行加密
}



function correctCharCode(num, charCode) {
    var resulst_chareCode = 0;
    if (num >= 65 && num <= 90){
        if (charCode < 65) { resulst_chareCode= charCode + 26;}
        else if (charCode > 90) { resulst_chareCode= charCode - 26;}
        else {
            return charCode
        }//大写字母加解密处理
    } else if ( num >= 97 && num <= 122){
        if (charCode < 97) {resulst_chareCode = charCode + 26;}
        else if (charCode > 122) {resulst_chareCode = charCode -26;}
        else {
            return charCode;
        }//小写字母加解密处理

    }

    return resulst_chareCode;
}




