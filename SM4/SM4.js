window.onload = init;

function init() {
  var plaintextInput = document.getElementById("plaintextInput"); //明文输入文本框
  var keyInput = document.getElementById("keyInput");   //明文密钥输入框
  var buttonOne = document.getElementById("buttonOne");  //加密按钮
  var messageArea = document.getElementById("MessageArea");  //密文显示
  var ciphertextInput = document.getElementById("ciphertextInput"); //密文输入文本框
  var key_oneInput = document.getElementById("key_oneInput");  //解密密钥
  var buttonTwo = document.getElementById("buttonTwo");  //解密按钮
  var messageAreaTwo = document.getElementById("MessageAreaTwo"); //明文显示


  buttonOne.onclick = function () {
    const size = 32;
    var key = keyInput.value;
    var bits_flow = transform_bits(key);  //128bits
    var FK = ["A3B1BAC6", "56AA3350", "677D9197", "B27022DC"];
    var FK_bits = [];
    for (var i = 0; i < FK.length; i++) {
      var son_bits = trans_sixteen_to_two(FK[i]);
      FK_bits.push(son_bits);
    }  //FK 转化为二进制 并且 存入数组

    var CK = ['00070e15', '1c232a31', '383f464d', '545b6269',
      '70777e85', '8c939aa1', 'a8afb6bd', 'c4cbd2d9',
      'e0e7eef5', 'fc030a11', '181f262d', '343b4249',
      '50575e65', '6c737a81', '888f969d', 'a4abb2b9',
      'c0c7ced5', 'dce3eaf1', 'f8ff060d', '141b2229',
      '30373e45', '4c535a61', '686f767d', '848b9299',
      'a0a7aeb5', 'bcc3cad1', 'd8dfe6ed', 'f4fb0209',
      '10171e25', '2c333a41', '484f565d', '646b7279'];
    var CK_bits = [];
    for (var i = 0; i < CK.length; i++) {
      CK_bits.push(trans_sixteen_to_two(CK[i]));
    }


    var initial_key = [];   //初始密钥
    for (var i = 0; i < (bits_flow.length / size); i++) {
      var son_bits = bits_flow.substring(i * size, (i + 1) * size);
      initial_key.push(xor(son_bits, FK_bits[i]));
    }

//产生轮密钥
    var RK_array = [];  //存储轮密钥
    for (var round = 0; round < 32; round++) {
      var RK = xor(initial_key[0], T_transform(initial_key[1], initial_key[2], initial_key[3], CK_bits[round], 0));
      initial_key = [initial_key[1], initial_key[2], initial_key[3], RK];
      RK_array.push(RK);
    }


    var plaintext = plaintextInput.value;
    var plain_bits = makeup(transform_bits(plaintext));

    //分组加密
    var total_cipher = "";
    for (var block = 0; block < (plain_bits.length / 128); block++) {


      var block_bits = plain_bits.substring(block * 128, (block + 1) * 128);
      var X_Array = [];
      for (var i = 0; i < (block_bits.length / size); i++) {
        var X = block_bits.substring(i * size, (i + 1) * size);
        X_Array.push(X);
      }

      //轮加密

      for (var i = 0; i < 32; i++) {
        var next_X = xor(X_Array[0], T_transform(X_Array[1], X_Array[2], X_Array[3], RK_array[i], 1));
        X_Array = [X_Array[1], X_Array[2], X_Array[3], next_X];

      }

      var Y_Array = X_Array.reverse();
      var cipher_bitsFlow = Y_Array.join("");
      var cipher = trans_tow_to_sixteen(cipher_bitsFlow);

      total_cipher += cipher;
    }

    messageArea.innerHTML = total_cipher;
  }  //加密
  buttonTwo.onclick = function () {
    const size = 32;
    var key = key_oneInput.value;
    var bits_flow = transform_bits(key);  //128bits
    var FK = ["A3B1BAC6", "56AA3350", "677D9197", "B27022DC"];
    var FK_bits = [];
    for (var i = 0; i < FK.length; i++) {
      var son_bits = trans_sixteen_to_two(FK[i]);
      FK_bits.push(son_bits);
    }  //FK 转化为二进制 并且 存入数组

    var CK = ['00070e15', '1c232a31', '383f464d', '545b6269',
      '70777e85', '8c939aa1', 'a8afb6bd', 'c4cbd2d9',
      'e0e7eef5', 'fc030a11', '181f262d', '343b4249',
      '50575e65', '6c737a81', '888f969d', 'a4abb2b9',
      'c0c7ced5', 'dce3eaf1', 'f8ff060d', '141b2229',
      '30373e45', '4c535a61', '686f767d', '848b9299',
      'a0a7aeb5', 'bcc3cad1', 'd8dfe6ed', 'f4fb0209',
      '10171e25', '2c333a41', '484f565d', '646b7279'];
    var CK_bits = [];
    for (var i = 0; i < CK.length; i++) {
      CK_bits.push(trans_sixteen_to_two(CK[i]));
    }


    var initial_key = [];   //初始密钥
    for (var i = 0; i < (bits_flow.length / size); i++) {
      var son_bits = bits_flow.substring(i * size, (i + 1) * size);
      initial_key.push(xor(son_bits, FK_bits[i]));
    }

//产生轮密钥
    var RK_array = [];  //存储轮密钥
    for (var round = 0; round < 32; round++) {
      var RK = xor(initial_key[0], T_transform(initial_key[1], initial_key[2], initial_key[3], CK_bits[round], 0));
      initial_key = [initial_key[1], initial_key[2], initial_key[3], RK];
      RK_array.push(RK);
    }





    var cipher = ciphertextInput.value;
    var cipher_bitFlow = trans_sixteen_to_two(cipher);  //密文bits
    //分块解密
    var total_plainbits = "";
    for (var block = 0; block < (cipher_bitFlow.length / 128); block++) {
      var cipher_block = cipher_bitFlow.substring(block * 128, (block + 1) * 128);
      var Y_array = [];

      for (var i = 0; i < (cipher_block.length / size); i++) {
        var Y = cipher_block.substring(i * size, (i + 1) * size);
        Y_array.push(Y)
      }
      Y_array = Y_array.reverse();
      for (var i = 0; i < 32; i++) {
        var former_X = xor(Y_array[3], T_transform(Y_array[0], Y_array[1], Y_array[2], RK_array[31 - i], 1));
        Y_array = [former_X, Y_array[0], Y_array[1], Y_array[2]];
      }

      var plaintext__ = Y_array.join("");
      total_plainbits += plaintext__;
    }

    messageAreaTwo.innerHTML = transformChar(total_plainbits);
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
    setTimeout(buttonTwo.click(), 3000);
  }
  //使用回车键快便捷输入解密密钥

  keyInput.onkeypress = function (enter) {
    if (enter.keyCode === 13){
      buttonOne.click();
    }
  }
  //使用回车进行加密
}

function transform_bits(string){
  var result_bits = "";
  const size = 8;
  for(var i = 0; i < string.length; i++){
    var bits = string[i].charCodeAt().toString(2);
    var len = bits.length;
    for ( var j = 0; j < (size - len); j++){
      bits = '0' + bits;
    }
    result_bits += bits;
  }
  return result_bits;
}  //字符转化为bits流

function trans_tow_to_sixteen(bitsFlow){
  const size = 4;
  var string = "";
  for (var i = 0; i < (bitsFlow.length / size); i++){
    var bits = bitsFlow.substring(i * size, ( i + 1) * size);
    var str = parseInt(bits, 2).toString(16);
    string += str;
  }

  return string;
}  //2进制转16进制

function trans_sixteen_to_two(bitsFlow){
  var string = "";
  const len = 4;
  for (var i = 0; i < bitsFlow.length; i++){
    var num = parseInt(bitsFlow[i], 16).toString(2);
    var length = num.length
    if(num.length < 4){
      for (var j = 0; j < (len - length); j++){
        num = "0" + num;
      }
    }

    string += num;
  }

  return string;
} // 16进制 - 2进制

function shiftLeft(string, n){
  var len = string.length;
  n = n % len;  // 避免n大于字符串长度

  return string.substring(n, len) + string.substring(0, n);
}  //字符串循环左移

function xor(bitsFlow, bitFlows_two){
  var result_bitsFlow = "";
  for (var i = 0; i < bitsFlow.length; i++){
    var result = bitsFlow[i] ^ bitFlows_two[i];
    result_bitsFlow += result;
  }
  return result_bitsFlow;
}  //二进制字符串逐位异或

function T_transform(key1, key2, key3, argu, option) {
  const size = 8
  var S_box = [
    ['d6', '90', 'e9', 'fe', 'cc', 'e1', '3d', 'b7', '16', 'b6', '14', 'c2', '28', 'fb', '2c', '05'],
    ['2b', '67', '9a', '76', '2a', 'be', '04', 'c3', 'aa', '44', '13', '26', '49', '86', '06', '99'],
    ['9c', '42', '50', 'f4', '91', 'ef', '98', '7a', '33', '54', '0b', '43', 'ed', 'cf', 'ac', '62'],
    ['e4', 'b3', '1c', 'a9', 'c9', '08', 'e8', '95', '80', 'df', '94', 'fa', '75', '8f', '3f', 'a6'],
    ['47', '07', 'a7', 'fc', 'f3', '73', '17', 'ba', '83', '59', '3c', '19', 'e6', '85', '4f', 'a8'],
    ['68', '6b', '81', 'b2', '71', '64', 'da', '8b', 'f8', 'eb', '0f', '4b', '70', '56', '9d', '35'],
    ['1e', '24', '0e', '5e', '63', '58', 'd1', 'a2', '25', '22', '7c', '3b', '01', '21', '78', '87'],
    ['d4', '00', '46', '57', '9f', 'd3', '27', '52', '4c', '36', '02', 'e7', 'a0', 'c4', 'c8', '9e'],
    ['ea', 'bf', '8a', 'd2', '40', 'c7', '38', 'b5', 'a3', 'f7', 'f2', 'ce', 'f9', '61', '15', 'a1'],
    ['e0', 'ae', '5d', 'a4', '9b', '34', '1a', '55', 'ad', '93', '32', '30', 'f5', '8c', 'b1', 'e3'],
    ['1d', 'f6', 'e2', '2e', '82', '66', 'ca', '60', 'c0', '29', '23', 'ab', '0d', '53', '4e', '6f'],
    ['d5', 'db', '37', '45', 'de', 'fd', '8e', '2f', '03', 'ff', '6a', '72', '6d', '6c', '5b', '51'],
    ['8d', '1b', 'af', '92', 'bb', 'dd', 'bc', '7f', '11', 'd9', '5c', '41', '1f', '10', '5a', 'd8'],
    ['0a', 'c1', '31', '88', 'a5', 'cd', '7b', 'bd', '2d', '74', 'd0', '12', 'b8', 'e5', 'b4', 'b0'],
    ['89', '69', '97', '4a', '0c', '96', '77', '7e', '65', 'b9', 'f1', '09', 'c5', '6e', 'c6', '84'],
    ['18', 'f0', '7d', 'ec', '3a', 'dc', '4d', '20', '79', 'ee', '5f', '3e', 'd7', 'cb', '39', '48']
  ];
  var mid_bits = xor( xor( xor(key1,key2), key3), argu);  //32bits
  var S_bits = "";
  for (var i = 0; i < mid_bits.length / 8; i++){
    var son_bisFlow = mid_bits.substring(i * size, (i + 1) * size);
    var y_index = parseInt(son_bisFlow[4] + son_bisFlow[5] + son_bisFlow[6] + son_bisFlow[7], 2);
    var x_index = parseInt(son_bisFlow[0] + son_bisFlow[1] + son_bisFlow[2] + son_bisFlow[3], 2);
    var result_bits = trans_sixteen_to_two(S_box[y_index][x_index]);
    S_bits += result_bits;
  }

  if(option === 0){
    var result_bitsFlow = xor( xor(S_bits, shiftLeft(S_bits, 13)), shiftLeft(S_bits, 23) );}

  else{
    var result_bitsFlow = xor(xor( xor(S_bits, shiftLeft(S_bits, 2)), shiftLeft(S_bits, 10)), shiftLeft(S_bits, 18), shiftLeft(S_bits, 24));
  }


  return result_bitsFlow;
}  //T置换

function makeup(bitsFlow){
  const size = 128;
  var len = bitsFlow.length;
  if (bitsFlow.length % size !== 0){
    for (var i = 0; i < size - (len % size); i++){
      bitsFlow += "0";
    }
  }

  return bitsFlow
} //将明文填充为128bits的倍数

function transformChar(bitsFlow){
  const size = 8;
  var string = "";
  for (var i = 0; i < (bitsFlow.length / size); i ++){
    var bits = bitsFlow.substring(i * size, (i + 1) * size);
    var str = String.fromCharCode(parseInt(bits, 2));

    string += str;
  }
  return string;
}  //bits流转化为字符串