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
    function round_process(bitsFlow, round_num) {
      var next_bitsFlow = "";
      var L_flow = bitsFlow.substring(0, size / 2);
      var R_flow = bitsFlow.substring(size / 2, size);
      var next_Lflow = R_flow;
      R_flow = Pbox_transform(Sbox_transform(xor(expand_transform(R_flow), key_array[round_num])));   //扩展变换 与密钥异或 48bits

      var next_Rflow = xor(R_flow, L_flow);

      next_bitsFlow = next_Lflow + next_Rflow;

      return next_bitsFlow;
    }  //产生L、R
    function round_processLast(bitsFlow) {
      const size = 64;
      var next_bitsFlow = "";
      var L_flow = bitsFlow.substring(0, size / 2);
      var R_flow = bitsFlow.substring(size / 2, size);
      var next_Rflow = R_flow;
      R_flow = Pbox_transform(Sbox_transform(xor(expand_transform(R_flow), key_array[round - 1])));  //扩展变换 与密钥异或 48bits

      var next_Lflow = xor(L_flow, R_flow);

      next_bitsFlow = next_Lflow + next_Rflow;

      return next_bitsFlow;
    }

    const size = 64;
    const round = 16;
    var plaintext = plaintextInput.value;
    var keyText = keyInput.value;
    var plaintext_bits = makeup(transformBitsFlow(plaintext));
    var plaintext_len = plaintext_bits.length;

    //密钥拓展
    var key_first = PC_one(odd_even_check(transformBitsFlow(keyText))); //将密钥转化为二进制数，并实现偶校验与PC-1拣选变换 64bits - 56bits
    //产生轮密钥
    var key_array = [];  //存储16轮密钥
    for (var r = 1; r <= round; r++) {
      var C_D = C_Add_D(key_first, r);
      var key = generate_key(C_D);
      key_array.push(key);
    }


    //对明文进行分块加密
    var total_plainBits = "";
    for (var i = 0; i <= (plaintext_len - size); i += size) {  //分组
      var plaintext_bit = plaintext_bits.substring(i, i + size);
      var result_bits = "";
      var roundProcess_LR = [];  //存储16轮加密过程的中间量
      plaintext_bit = IP(plaintext_bit); //IP置换
      for (var j = 0; j < (round - 1); j++) {
        var result_plaintext = "";
        if (j === 0) {
          result_plaintext = round_process(plaintext_bit, j)
        }
        else {
          result_plaintext = round_process(roundProcess_LR[j - 1], j)
        }

        roundProcess_LR.push(result_plaintext);

      }

      var bits_15process = roundProcess_LR[round - 2]; //64bits
      result_bits = IPN(round_processLast(bits_15process));

      total_plainBits += result_bits;
    }

    messageArea.innerHTML = trans_tow_to_sixteen(total_plainBits); //16进制数显示密文

  }   //加密

  buttonTwo.onclick = function () {
    function round_processfirst(bitsFlow) {
      var former_bitsFlow = "";
      var L_flow = bitsFlow.substring(0, size / 2);
      var R_flow = bitsFlow.substring(size / 2, size);
      var former_Rflow = R_flow;
      R_flow = Pbox_transform(Sbox_transform(xor(expand_transform(R_flow), key_array[round - 1])));
      var former_Lflow = xor(R_flow, L_flow);
      former_bitsFlow = former_Lflow + former_Rflow;

      return former_bitsFlow;
    }

    function return_round_process(bitsFlow, i) {
      var former_bitsFlow = "";
      var L_flow = bitsFlow.substring(0, size / 2);
      var R_flow = bitsFlow.substring(size / 2, size);
      var former_Rflow = L_flow;
      var former_Lflow = xor(Pbox_transform(Sbox_transform(xor(expand_transform(former_Rflow), key_array[14 - i]))), R_flow);

      former_bitsFlow = former_Lflow + former_Rflow;

      return former_bitsFlow;
    }  

    const size = 64;
    const round = 16;
    var ciphertext = ciphertextInput.value;
    var keyText = key_oneInput.value;
    var ciphertext_bits = trans_sixteen_to_two(ciphertext);  //64bits的整数倍
    var ciphertext_len = ciphertext_bits.length;

    //密钥拓展
    var key_first = PC_one(odd_even_check(transformBitsFlow(keyText))); //将密钥转化为二进制数，并实现偶校验与PC-1拣选变换 64bits - 56bits
    //产生轮密钥
    var key_array = [];  //存储16轮密钥
    for (var r = 1; r <= round; r++) {
      var C_D = C_Add_D(key_first, r);
      var key = generate_key(C_D);
      key_array.push(key);
    }

    //对密文进行分块解密
    var total_plainBits = "";
    for (var i = 0; i < (ciphertext_len / size); i++) {
      var son_ciphertext = ciphertext_bits.substring(i * size, (i + 1) * size);
      var roundProcess_LR = []; // 存储16轮解密过程的中间量
      var result_bits = "";
      son_ciphertext = round_processfirst(IP(son_ciphertext)); //IP置换 并第一轮解密
      for (var j = 0; j < (round - 1); j++) {
        var former_bits = "";
        if (j === 0) {
          former_bits = return_round_process(son_ciphertext, j)
        }

        else {
          former_bits = return_round_process(roundProcess_LR[j - 1], j);
        }

        roundProcess_LR.push(former_bits);

      }

      var bits_15process = IPN(roundProcess_LR[round - 2]);
      result_bits = bits_15process;
      total_plainBits += result_bits;
    }

     messageAreaTwo.innerHTML = transformChar(total_plainBits);

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

    setTimeout(buttonTwo.click(), 2000);
  }
  //使用回车键快便捷输入解密密钥

  keyInput.onkeypress = function (enter) {
    if (enter.keyCode === 13){
      buttonOne.click();
    }
  }
  //使用回车进行加密

}

function makeup(bitsFlow) {
  const size = 64;
  var len = bitsFlow.length;
  if (bitsFlow.length % size !== 0) {
    for (var i = 0; i < size - (len % size); i++) {
      bitsFlow += "0";
    }
  }
  return bitsFlow;
} //明文长度填充为64bits的倍数

function transformBitsFlow(string){
  const len = 8;
  var bitsFlow = "";
  for ( var i = 0; i < string.length; i++){
    var bit = string[i].charCodeAt().toString(2);
    var BitLength = bit.length;
    for ( var j = 0; j < (len - BitLength); j++){
      bit = "0" + bit;
    }
    bitsFlow += bit;
  }

  return bitsFlow;
} //将7位密钥转化为56位二进制比特流

function odd_even_check(bitsFlow) {
  const size = 7;
  var key = "";
  for (var i = 0; i <= (bitsFlow.length - size); i += size){
    var sum = 0;
    var subString = bitsFlow.substring(i, i + size);
    for (var j = 0; j < subString.length; j++){
      var num = Number(subString[j]);
      sum += num;
    }

    if (sum % 2 === 0) {
      subString += "0";}
    else{
      subString += "1";}
      
    key += subString;
  }

  return key;
}//奇偶校验   56bits - 64bits

function PC_one(bitsFlow){
  var switch_bitsFlow = bitsFlow[56] + bitsFlow[48] + bitsFlow[40] + bitsFlow[32] + bitsFlow[24] + bitsFlow[16] + bitsFlow[8] + bitsFlow[0] +
      bitsFlow[57] + bitsFlow[49] + bitsFlow[41] + bitsFlow[33] + bitsFlow[25] + bitsFlow[17] + bitsFlow[9] + bitsFlow[1] +
      bitsFlow[58] + bitsFlow[50] + bitsFlow[42] + bitsFlow[34] + bitsFlow[26] + bitsFlow[18] + bitsFlow[10] + bitsFlow[20] +
      bitsFlow[59] + bitsFlow[51] + bitsFlow[43] + bitsFlow[35] + bitsFlow[62] + bitsFlow[54] + bitsFlow[46] + bitsFlow[38] +
      bitsFlow[30] + bitsFlow[22] + bitsFlow[14] + bitsFlow[6] + bitsFlow[61] + bitsFlow[53] + bitsFlow[45] + bitsFlow[37] +
      bitsFlow[29] + bitsFlow[21] + bitsFlow[13] + bitsFlow[5] + bitsFlow[60] + bitsFlow[52] + bitsFlow[44] + bitsFlow[36] +
      bitsFlow[28] + bitsFlow[20] + bitsFlow[12] + bitsFlow[4] + bitsFlow[27] + bitsFlow[19] + bitsFlow[11] + bitsFlow[3];
  return switch_bitsFlow;
}   //pc-1 拣选变换   64bits - 56bits

function C_Add_D(bitsFlow, count) {
  var C_flow = bitsFlow.substring(0, bitsFlow.length/2);
  var D_flow = bitsFlow.substring(bitsFlow.length/2, bitsFlow.length);
  var result_bitsFlow = "";
  switch (count) {
    case 1:{C_flow = shiftLeft(C_flow, 1);
      D_flow = shiftLeft(D_flow, 1);} break;

    case 2:{C_flow = shiftLeft(C_flow, 2);
      D_flow = shiftLeft(D_flow, 2);} break;

    case 3:{C_flow = shiftLeft(C_flow, 4);
      D_flow = shiftLeft(D_flow, 4);} break;

    case 4:{C_flow = shiftLeft(C_flow, 6);
      D_flow = shiftLeft(D_flow, 6);} break;

    case 5:{C_flow = shiftLeft(C_flow, 8);
      D_flow = shiftLeft(D_flow, 8);} break;

    case 6:{C_flow = shiftLeft(C_flow, 10);
      D_flow = shiftLeft(D_flow, 10);} break;

    case 7:{C_flow = shiftLeft(C_flow, 12);
      D_flow = shiftLeft(D_flow, 12);} break;

    case 8:{C_flow = shiftLeft(C_flow, 14);
      D_flow = shiftLeft(D_flow, 14);} break;

    case 9:{C_flow = shiftLeft(C_flow, 15);
      D_flow = shiftLeft(D_flow, 15);} break;

    case 10:{C_flow = shiftLeft(C_flow, 17);
      D_flow = shiftLeft(D_flow, 17);} break;

    case 11:{C_flow = shiftLeft(C_flow, 19);
      D_flow = shiftLeft(D_flow, 19);} break;

    case 12:{C_flow = shiftLeft(C_flow, 21);
      D_flow = shiftLeft(D_flow, 21);} break;

    case 13:{C_flow = shiftLeft(C_flow, 23);
      D_flow = shiftLeft(D_flow, 23);} break;

    case 14:{C_flow = shiftLeft(C_flow, 25);
      D_flow = shiftLeft(D_flow, 25);} break;

    case 15:{C_flow = shiftLeft(C_flow, 27);
      D_flow = shiftLeft(D_flow, 27);} break;

    case 16:{C_flow = shiftLeft(C_flow, 28);
      D_flow = shiftLeft(D_flow, 28);} break;

  }

  result_bitsFlow = C_flow + D_flow;
  return result_bitsFlow;
} //循环移位 产生下一轮C、D 56bits

function generate_key(bitsFlow){
  var key = "";
  key = bitsFlow[13] + bitsFlow[16] + bitsFlow[10] + bitsFlow[23] + bitsFlow[0] + bitsFlow[4] + bitsFlow[2] + bitsFlow[27] +
      bitsFlow[14] + bitsFlow[5] + bitsFlow[20] + bitsFlow[9] + bitsFlow[22] + bitsFlow[18] + bitsFlow[11] + bitsFlow[3] +
      bitsFlow[25] + bitsFlow[7] + bitsFlow[15] + bitsFlow[6] + bitsFlow[26] + bitsFlow[19] + bitsFlow[12] + bitsFlow[1] +
      bitsFlow[40] + bitsFlow[51] + bitsFlow[30] + bitsFlow[36] + bitsFlow[46] + bitsFlow[54] + bitsFlow[29] + bitsFlow[39] +
      bitsFlow[50] + bitsFlow[44] + bitsFlow[32] + bitsFlow[47] + bitsFlow[43] + bitsFlow[48] + bitsFlow[38] + bitsFlow[55] +
      bitsFlow[33] + bitsFlow[52] + bitsFlow[45] + bitsFlow[41] + bitsFlow[49] + bitsFlow[35] + bitsFlow[28] + bitsFlow[31];

  return key;
} //pc-2 产生轮密钥 56bits - 48bits

function shiftLeft(string, n){
  var len = string.length;
  n = n % len;  // 避免n大于字符串长度

  return string.substring(n, len) + string.substring(0, n);
}  //字符串循环左移

function IP (bitsFlow){
  var result_bitsFlow = bitsFlow[57] + bitsFlow[49] + bitsFlow[41] + bitsFlow[33] + bitsFlow[25] + bitsFlow[17] + bitsFlow[9] + bitsFlow[1] +
      bitsFlow[59] + bitsFlow[51] + bitsFlow[43] + bitsFlow[35] + bitsFlow[27] + bitsFlow[19] + bitsFlow[11] + bitsFlow[3] +
      bitsFlow[61] + bitsFlow[53] + bitsFlow[45] + bitsFlow[37] + bitsFlow[29] + bitsFlow[21] + bitsFlow[13] + bitsFlow[5] +
      bitsFlow[63] + bitsFlow[55] + bitsFlow[47] + bitsFlow[39] + bitsFlow[31] + bitsFlow[23] + bitsFlow[15] + bitsFlow[7] +
      bitsFlow[56] + bitsFlow[48] + bitsFlow[40] + bitsFlow[32] + bitsFlow[24] + bitsFlow[16] + bitsFlow[8] + bitsFlow[0] +
      bitsFlow[58] + bitsFlow[50] + bitsFlow[42] + bitsFlow[34] + bitsFlow[26] + bitsFlow[18] + bitsFlow[10] + bitsFlow[2] +
      bitsFlow[60] + bitsFlow[52] + bitsFlow[44] + bitsFlow[36] + bitsFlow[28] + bitsFlow[20] + bitsFlow[12] + bitsFlow[4] +
      bitsFlow[62] + bitsFlow[54] + bitsFlow[46] + bitsFlow[38] + bitsFlow[30] + bitsFlow[22] + bitsFlow[14] + bitsFlow[6] ;

  return result_bitsFlow;
}  //IP 置换

function expand_transform(bitsFlow){
  var result_bitsFlow = "";
  result_bitsFlow = bitsFlow[31] + bitsFlow[0] + bitsFlow[1] + bitsFlow[2] + bitsFlow[3] + bitsFlow[4] +
                bitsFlow[3] + bitsFlow[4] + bitsFlow[5] + bitsFlow[6] + bitsFlow[7] + bitsFlow[8] +
                bitsFlow[7] + bitsFlow[8] + bitsFlow[9] + bitsFlow[10] + bitsFlow[11] + bitsFlow[12] +
                bitsFlow[11] + bitsFlow[12] + bitsFlow[13] + bitsFlow[14] + bitsFlow[15] + bitsFlow[16] +
                bitsFlow[15] + bitsFlow[16] + bitsFlow[17] + bitsFlow[18] + bitsFlow[19] + bitsFlow[20] +
                bitsFlow[19] + bitsFlow[20] + bitsFlow[21] + bitsFlow[22] + bitsFlow[23] + bitsFlow[24] +
                bitsFlow[23] + bitsFlow[24] + bitsFlow[25] + bitsFlow[26] + bitsFlow[27] + bitsFlow[28] +
                bitsFlow[27] + bitsFlow[28] + bitsFlow[29] + bitsFlow[30] + bitsFlow[31] + bitsFlow[0] ;
  return result_bitsFlow;
}  //扩展变换 32bits - 48bits

function xor(bitsFlow, key){
  var result_bitsFlow = "";
  for (var i = 0; i < bitsFlow.length; i++){
    var result = bitsFlow[i] ^ key[i];
    result_bitsFlow += result;
  }
  return result_bitsFlow;
}  //二进制字符串逐位异或 48bits

function Sbox_transform(bitsFlow){
  const size = 6;
  var bitsFlow_len = bitsFlow.length;
  var result_bitsFlow = "";
  var Sbox_array = [
    [ [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
      [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
      [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
      [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]  ], //box_S1

    [ [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
      [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
      [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
      [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9] ], //box_S2

    [ [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
      [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
      [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
      [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12] ], //box_S3

    [ [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
      [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
      [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
      [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14] ], //box_S4

    [ [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
      [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
      [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
      [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3] ], //box_S5

    [ [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
      [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
      [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
      [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13] ], //box_S6

    [ [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
      [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
      [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
      [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12] ], //box_S7

    [ [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
      [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
      [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
      [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11] ] //box_S8


  ];

  for (var i = 0; i < (bitsFlow_len / size); i++){
    var bitsflow = bitsFlow.substring(i * size, (i + 1) * size);
    var y_index = parseInt(bitsflow[0] + bitsflow[size -1], 2);
    var x_index = parseInt(bitsflow[1] + bitsflow[2] + bitsflow[3] + bitsflow[4], 2);
    var result_bitsflow = Sbox_array[i][y_index][x_index].toString(2);
    var len = result_bitsflow.length;
    for (var j = 0; j < (4 - len); j++){
      result_bitsflow = "0" + result_bitsflow;
    }

    result_bitsFlow += result_bitsflow;
  }

  return result_bitsFlow
}  //s盒置换 48bits - 32bits

function Pbox_transform(bitsFlow){
  var result_bitsFlow = bitsFlow[15] + bitsFlow[6] + bitsFlow[19] + bitsFlow[20] +
      bitsFlow[28] + bitsFlow[11] + bitsFlow[27] + bitsFlow[16] +
      bitsFlow[0] + bitsFlow[14] + bitsFlow[22] + bitsFlow[25] +
      bitsFlow[4] + bitsFlow[17] + bitsFlow[30] + bitsFlow[9] +
      bitsFlow[1] + bitsFlow[7] + bitsFlow[23] + bitsFlow[13] +
      bitsFlow[31] + bitsFlow[26] + bitsFlow[2] + bitsFlow[8] +
      bitsFlow[18] + bitsFlow[12] + bitsFlow[29] + bitsFlow[5] +
      bitsFlow[21] + bitsFlow[10] + bitsFlow[3] + bitsFlow[24] ;

  return result_bitsFlow;
} //P盒置换 32bits - 32bits

function IPN (bitsFlow){
  var result_bitsFlow = bitsFlow[39] + bitsFlow[7] + bitsFlow[47] + bitsFlow[15] + bitsFlow[55] + bitsFlow[23] + bitsFlow[63] + bitsFlow[31] +
                bitsFlow[38] + bitsFlow[6] + bitsFlow[46] + bitsFlow[14] + bitsFlow[54] + bitsFlow[22] + bitsFlow[62] + bitsFlow[30] +
                bitsFlow[37] + bitsFlow[5] + bitsFlow[45] + bitsFlow[13] + bitsFlow[53] + bitsFlow[21] + bitsFlow[61] + bitsFlow[29] +
                bitsFlow[36] + bitsFlow[4] + bitsFlow[44] + bitsFlow[12] + bitsFlow[52] + bitsFlow[20] + bitsFlow[60] + bitsFlow[28] +
                bitsFlow[35] + bitsFlow[3] + bitsFlow[43] + bitsFlow[11] + bitsFlow[51] + bitsFlow[19] + bitsFlow[59] + bitsFlow[27] +
                bitsFlow[34] + bitsFlow[2] + bitsFlow[42] + bitsFlow[10] + bitsFlow[50] + bitsFlow[18] + bitsFlow[58] + bitsFlow[26] +
                bitsFlow[33] + bitsFlow[1] + bitsFlow[41] + bitsFlow[9] + bitsFlow[49] + bitsFlow[17] + bitsFlow[57] + bitsFlow[25] +
                bitsFlow[32] + bitsFlow[0] + bitsFlow[40] + bitsFlow[8] + bitsFlow[48] + bitsFlow[16] + bitsFlow[56] + bitsFlow[24] ;
  return result_bitsFlow;
  }  //Ip 逆置换 64bits

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


function trans_tow_to_sixteen(bitsFlow){
  const size = 4;
  var string = "";
  for (var i = 0; i < (bitsFlow.length / size); i++){
    var bits = bitsFlow.substring(i * size, ( i + 1) * size);
    var str = parseInt(bits, 2).toString(16);
    string += str;
  }

  return string;


}  //以16进制数显示密文

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
} // 16进制 - 12进制






