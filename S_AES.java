import java.util.Arrays;
import java.util.ArrayList;
import javax.swing.*;
import java.awt.event.*;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

public class S_AES {

    JFrame f1,f2,f3,f4,f5,f6;
    JButton b1,b2,b3,b4,b5,b6,b7,b8,b9,b10,b11,b12,b13,b14,b15,b16,b17,b18,b19;
    JTextField text1,text2,text3,text4,text5,text6,text7,text8,text9,text10,text11;
    JLabel label1,label2,label3,label4,label5,label6,label7,label8,label9,label10,label11,label12,label13,label14,label15,label16;
    myListener listener1,listener5,listener6,listener12,listener13,listener14,listener15;
    anotherListener listener17,listener18;
    ActionListener listener2,listener3,listener4,listener7,listener8,listener9,listener10,listener11,listener16,listener19;

    public static void main(String[] args) {
        new S_AES();
    }

    public static String encryptCBC(String plaintext1, String key, String iv) {
        int blockSize = 16; // 16位AES块大小

        // 分组明文
        String plaintext = convertStringToBin(plaintext1);
        String[] blocks = splitToBlocks(plaintext, blockSize);
        String previousCipherBlock = iv; // 初始化前一个密文块为初始向量

        String encryptedText1 = "";

        for (String block : blocks) {
            // 在CBC模式中，每个块先与前一个密文块异或，然后加密
            String xorResult = xorStrings16(block, previousCipherBlock);
            String cipherBlock = encrypt(xorResult, key);
            previousCipherBlock = cipherBlock; // 更新前一个密文块

            encryptedText1 += cipherBlock;
        }
        String encryptedText = convertBinToString(encryptedText1);
        return encryptedText;
    }

    public static String decryptCBC(String ciphertext1, String key, String iv) {
        int blockSize = 16; // 16位AES块大小
        String ciphertext = convertStringToBin(ciphertext1);
        // 分组密文
        String[] blocks = splitToBlocks(ciphertext, blockSize);
        String previousCipherBlock = iv;

        String decryptedText1 = "";

        for (String block : blocks) {
            String decryptedBlock = decrypt(block, key);
            String xorResult = xorStrings16(decryptedBlock, previousCipherBlock);

            previousCipherBlock = block;

            decryptedText1 += xorResult;
            //System.out.println(decryptedText1);
        }
        String decryptedText = convertBinToString(decryptedText1);
        return decryptedText;
    }

    public static String xorStrings16(String a, String b) {
        int intA = Integer.parseInt(a, 2);
        int intB = Integer.parseInt(b, 2);
        int result = intA ^ intB;
        return String.format("%16s", Integer.toBinaryString(result)).replace(' ', '0');
    }

    public static String[] splitToBlocks(String text, int blockSize) {
        int len = text.length();
        int numBlocks = (int) Math.ceil((double) len / blockSize);
        String[] blocks = new String[numBlocks];

        for (int i = 0; i < numBlocks; i++) {
            int start = i * blockSize;
            int end = Math.min((i + 1) * blockSize, len);
            blocks[i] = text.substring(start, end);
        }

        return blocks;
    }


    public static String encrypt(String plaintext, String key) {
        String state = plaintext;
        String[] roundKeys = keyExpansion(key);
        // System.out.println(roundKeys[0]);
        // System.out.println(roundKeys[1]);
        // System.out.println(roundKeys[2]);

        // 初始轮密钥加
        state = addRoundKey(state, roundKeys[0]);

        // 迭代2轮，模拟AES的操作
        for (int round = 1; round <= 2; round++) {
            state = subBytes(state); // 字节替代
            state = shiftRows(state); // 行位移
            if (round < 2) {
                state = mixColumns(state); // 列混淆（除最后一轮）
            }
            state = addRoundKey(state, roundKeys[round]); // 轮密钥加
        }

        return state;
    }

    public static String[] keyExpansion(String key) {
        String[] roundKeys = new String[3];
        roundKeys[0] = key;

        for (int round = 1; round <= 2; round++) {
            String previousKey = roundKeys[round - 1];
            String previousKey1 = previousKey.substring(0,8);
            String previousKey2 = previousKey.substring(8);
            String newKey1 = xorStrings(previousKey1, xorStrings(roundConstant(round), SubNib(previousKey2.substring(4))+SubNib(previousKey2.substring(0,4))));
            String newKey2 = xorStrings(previousKey2, newKey1);
            String newKey = newKey1 + newKey2;
            roundKeys[round] = newKey;
        }

        return roundKeys;
    }

    // public static String rotateWord(String word) {
    //     return word.substring(4) + word.substring(0, 4);
    // }

    public static String xorStrings(String a, String b) {
        int intA = Integer.parseInt(a, 2);
        int intB = Integer.parseInt(b, 2);
        int result = intA ^ intB;
        return String.format("%8s", Integer.toBinaryString(result)).replace(' ', '0');
    }

    public static String roundConstant(int round) {
        int[] rcon = {
            0x80, 0x30
        };
        return String.format("%08d", Integer.parseInt(Integer.toBinaryString(rcon[round - 1])));
    }

    public static String SubNib(String state) {
        String result = "";
        int row = Integer.parseInt(state.substring(0, 2), 2);
        int col = Integer.parseInt(state.substring(2, 4), 2);
        String s = Integer.toBinaryString(SBox[row][col]);
        while(s.length()<4){
            s = "0"+s;
        }
        result += s;
        return result;
    }

    public static String subBytes(String state) {
        String result = "";
        for (int i = 0; i < 16; i +=4) {
            String byteSub = state.substring(i, i + 4);
            int row = Integer.parseInt(byteSub.substring(0, 2), 2);
            int col = Integer.parseInt(byteSub.substring(2, 4), 2);
            String s = Integer.toBinaryString(SBox[row][col]);
            while(s.length()<4){
                s = "0"+s;
            }
            result += s;
        }
        return result;
    }

    public static String shiftRows(String state) {
        String row1 = state.substring(0, 4);
        String row2 = state.substring(4, 8);
        String row3 = state.substring(8, 12);
        String row4 = state.substring(12);

        return row1 + row4 + row3 + row2;
    }

    public static String mixColumns(String state) {
        String[] columns = new String[4];
        String[] rst = new String[4];
        int[] num1 = new int[4];
        int[] num2 = new int[4];
        for (int i = 0; i < 4; i++) {
            columns[i] = state.substring(4*i, 4*i + 4);
            num1[i] = Integer.parseInt(columns[i],2);
        }

        num2[0]= num1[0] ^ (galoisMult[num1[1]] [4]);
        num2[1]= num1[1] ^ (galoisMult[num1[0]] [4]);
        num2[2]= num1[2] ^ (galoisMult[num1[3]] [4]);
        num2[3]= num1[3] ^ (galoisMult[num1[2]] [4]);

        rst[0] = Integer.toBinaryString(num2[0]);
        rst[1] = Integer.toBinaryString(num2[1]);
        rst[2] = Integer.toBinaryString(num2[2]);
        rst[3] = Integer.toBinaryString(num2[3]);

        for (int i = 0; i < 4; i++) {
            while(rst[i].length()<4){
                rst[i] = "0"+rst[i];
            }
        }
        state = rst[0]+rst[1]+rst[2]+rst[3];
        return state;
    }

    private static final int[][] galoisMult = {
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {0, 2, 4, 6, 8, 10, 12, 14, 3, 1, 7, 5, 11, 9, 15, 13},
        {0, 3, 6, 5, 12, 15, 10, 9, 11, 8, 13, 14, 7, 4, 1, 2},
        {0, 4, 8, 12, 3, 7, 11, 15, 6, 2, 14, 10, 5, 1, 13, 9},
        {0, 5, 10, 15, 7, 2, 13, 8, 14, 11, 4, 1, 9, 12, 3, 6},
        {0, 6, 12, 10, 11, 13, 7, 1, 5, 3, 9, 15, 14, 8, 2, 4},
        {0, 7, 14, 9, 15, 8, 1, 6, 13, 10, 3, 4, 2, 5, 12, 11},
        {0, 8, 3, 11, 6, 14, 5, 13, 12, 4, 15, 7, 10, 2, 9, 1},
        {0, 9, 1, 8, 2, 11, 3, 10, 4, 13, 5, 12, 6, 15, 7, 14},
        {0, 10, 7, 13, 14, 4, 9, 15, 15, 5, 8, 2, 1, 11, 6, 12},
        {0, 11, 5, 14, 10, 1, 15, 4, 7, 12, 2, 9, 13, 6, 8, 3},
        {0, 12, 11, 7, 5, 9, 3, 15, 10, 6, 14, 2, 15, 3, 12, 4},
        {0, 13, 9, 4, 1, 12, 8, 5, 2, 15, 11, 6, 3, 14, 10, 7},
        {0, 14, 15, 1, 13, 3, 7, 11, 9, 7, 6, 8, 4, 2, 2, 13, 12},
        {0, 15, 13, 2, 9, 6, 4, 3, 1, 14, 12, 11, 7, 8, 10, 5}
    };

    public static String addRoundKey(String state, String roundKey) {
        int stateInt = Integer.parseInt(state, 2);
        int roundKeyInt = Integer.parseInt(roundKey, 2);
        int result = stateInt ^ roundKeyInt;
        return String.format("%16s", Integer.toBinaryString(result)).replace(' ', '0');
    }

    // S盒（字节替代表）
    private static final int[][] SBox = {
        {0x09, 0x04, 0x0A, 0x0B},
        {0x0D, 0x01, 0x08, 0x05},
        {0x06, 0x02, 0x00, 0x03},
        {0x0C, 0x0E, 0x0F, 0x07}
    };

    public static String decrypt(String ciphertext, String key) {
        String state = ciphertext;
        String[] roundKeys = keyExpansion(key);

        // 初始轮密钥加
        state = addRoundKey(state, roundKeys[2]);

        // 逆迭代2轮，模拟AES的解密操作
        for (int round = 1; round >= 0; round--) {
            state = invShiftRows(state); // 逆行位移
            state = invSubBytes(state); // 逆字节替代
            state = addRoundKey(state, roundKeys[round]); // 逆轮密钥加
            //System.out.println(state.length());
            if (round > 0) {
                state = invMixColumns(state); // 逆列混淆（除第一轮）
            }
            //System.out.println(state.length());
        }

        return state;
    }

    public static String invSubBytes(String state) {
        String result = "";
        for (int j = 0; j < 4; j++) {
            // System.out.println(j);
            // System.out.println(state.length());
            String byteSub = state.substring(4*j, 4*j + 4);
            int row = Integer.parseInt(byteSub.substring(0, 2), 2);
            int col = Integer.parseInt(byteSub.substring(2, 4), 2);
            String s = Integer.toBinaryString(InvSBox[row][col]);
            while(s.length()<4){
                s = "0"+s;
            }
            result += s;
        }
        return result;
    }

    public static String invShiftRows(String state) {
        String row1 = state.substring(0, 4);
        String row2 = state.substring(4, 8);
        String row3 = state.substring(8, 12);
        String row4 = state.substring(12);

        return row1 + row4 + row3 + row2;
    }

    public static String invMixColumns(String state) {
        String[] columns = new String[4];
        String[] rst = new String[4];
        int[] num1 = new int[4];
        int[] num2 = new int[4];
        for (int i = 0; i < 4; i++) {
            columns[i] = state.substring(4*i, 4*i + 4);
            num1[i] = Integer.parseInt(columns[i],2);
        }

        num2[0]= (galoisMult[num1[0]] [9]) ^ (galoisMult[num1[1]] [2]);
        num2[1]= (galoisMult[num1[1]] [9]) ^ (galoisMult[num1[0]] [2]);
        num2[2]= (galoisMult[num1[2]] [9]) ^ (galoisMult[num1[3]] [2]);
        num2[3]= (galoisMult[num1[3]] [9]) ^ (galoisMult[num1[2]] [2]);

        rst[0] = Integer.toBinaryString(num2[0]);
        rst[1] = Integer.toBinaryString(num2[1]);
        rst[2] = Integer.toBinaryString(num2[2]);
        rst[3] = Integer.toBinaryString(num2[3]);

        for (int i = 0; i < 4; i++) {
            while(rst[i].length()<4){
                rst[i] = "0"+rst[i];
            }
        }

        state = rst[0]+rst[1]+rst[2]+rst[3];
        return state;
    }

    // 逆S盒（逆字节替代表）
    private static final int[][] InvSBox = {
        {0x0A, 0x05, 0x09, 0x0B},
        {0x01, 0x07, 0x08, 0x0F},
        {0x06, 0x00, 0x02, 0x03},
        {0x0C, 0x04, 0x0D, 0x0E}
    };

    public static String convertStringToBin(String str){
 
        char[] chars = str.toCharArray();
   
        StringBuffer bin = new StringBuffer();
        for(int i = 0; i < chars.length; i++){
            String temp = Integer.toBinaryString((int)chars[i]);
            while(temp.length()<8){
                temp = "0" + temp;
            }
          bin.append(temp);
        }
   
        return bin.toString();
        }
   
    public static String convertBinToString(String bin){
   
        StringBuilder sb = new StringBuilder();
   
        //49204c6f7665204a617661 split into two characters 49, 20, 4c...
        for( int i=0; i<bin.length()-7; i+=8 ){
   
            //grab the hex in pairs
            String output = bin.substring(i, (i + 8));
            //convert hex to decimal
            int decimal = Integer.parseInt(output, 2);
            //convert the decimal to character
            sb.append((char)decimal);
        }
   
        return sb.toString();
    }

    public static String hexToBinary(String hexString) {
        // 将16进制字符串解析为整数
        int intValue = Integer.parseInt(hexString, 16);

        // 将整数转换为2进制字符串
        String binaryString = Integer.toBinaryString(intValue);

        // 可能需要在前面补零，以确保输出的字符串有16位（4位16进制对应16位2进制）
        while(binaryString.length()<16){
            binaryString = "0" + binaryString;
        }

        return binaryString;
    }

    static ArrayList<String> bf(String s1, String s2){
        ArrayList<String> key = new ArrayList<String>();
        for(int i=0; i<65536; i++){
            String x = Integer.toBinaryString(i);
            while(x.length()<16){
                x = "0"+x;
            }
            if(encrypt(s1, x).equals(s2)){
                key.add(x);
            }
        }
        return key;
    }

    public static String douencrypt(String Key, String plaintext) {
        String K1 = Key.substring(0,4);
        String K2 = Key.substring(4);
        K1 = hexToBinary(K1);
        K2 = hexToBinary(K2);
        //System.out.println(K1);
        //System.out.println(K2);
        String Ciphertext = encrypt(encrypt(plaintext, K1), K2);
        return Ciphertext;
    }

    public static String doudecrypt(String Key, String Ciphertext) {
        Key = hexToBinary(Key);
        String K1 = Key.substring(0,16);
        String K2 = Key.substring(16);
        String plaintext = decrypt(decrypt(Ciphertext, K2), K1);
        return plaintext;
    }

    public static String triencrypt(String Key, String plaintext) {
        Key = hexToBinary(Key);
        String K1 = Key.substring(0,16);
        String K2 = Key.substring(16);
        String Ciphertext = encrypt(decrypt(encrypt(plaintext, K1), K2), K1);
        return Ciphertext;
    }

    public static String tridecrypt(String Key, String Ciphertext) {
        Key = hexToBinary(Key);
        String K1 = Key.substring(0,16);
        String K2 = Key.substring(16);
        String plaintext = decrypt(encrypt(decrypt(Ciphertext, K1), K2), K1);
        return plaintext;
    }

    public static Map<String, String> createEncryptionTable() {
        Map<String, String> table = new TreeMap<>();
        for (int key = 0; key <= 0xFFFF; key++) {
            String plaintext = String.format("%04X", key);
            String ciphertext = encrypt(plaintext, plaintext); // 加密明文
            table.put(ciphertext, plaintext);
        }
        return table;
    }

    public static String findKey(Map<String, String> table, String intermediateResult) {
        return table.get(intermediateResult);
    }

    public static ArrayList<String> zhongjian(String knownPlaintext, String knownCiphertext) {
        ArrayList<String> Key = new ArrayList<String>();
        // 初始化一个表格，用于存储中间结果
        Map<String, String> intermediateResultTable = new HashMap<>();
        // 将已知密文解密得到中间结果
        for (int key = 0; key <= 0xFFFF; key++) {
            String keyHex1 = Integer.toBinaryString(key);
            while(keyHex1.length()<16){
                keyHex1 = "0" + keyHex1;
            }
            String intermediateResult = encrypt(knownPlaintext, keyHex1);
            intermediateResultTable.put(intermediateResult, keyHex1);
        }

        // 查表格以获取可能的密钥
        for (int key = 0; key <= 0xFFFF; key++){
            String keyHex2 = Integer.toBinaryString(key);
            while(keyHex2.length()<16){
                keyHex2 = "0" + keyHex2;
            }
            String intermediateResult = decrypt(knownCiphertext, keyHex2);
            String possibleKey = intermediateResultTable.get(intermediateResult);
            if (possibleKey != null) {
                Key.add(possibleKey+keyHex2);
            }
        }
        return Key;
    }

    public S_AES(){
        f1 = new JFrame("基本测试");
        f2 = new JFrame("S-AES");
        f3 = new JFrame("双重加解密");
        f4 = new JFrame("中间相遇攻击");
        f5 = new JFrame("三重加解密");
        f6 = new JFrame("工作模式");
        f1.setLayout(new FlowLayout());
        f2.setLayout(new FlowLayout());
        f3.setLayout(new FlowLayout());
        f4.setLayout(new FlowLayout());
        f5.setLayout(new FlowLayout());
        f6.setLayout(new FlowLayout());
        f1.setBounds(500,400,1000,200);
        f2.setBounds(800,400,500,150);
        f3.setBounds(500,400,1000,200);
        f4.setBounds(500,400,1200,200);
        f5.setBounds(500,400,1200,200);
        f6.setBounds(500,400,1200,200);
        f1.setVisible(false);
        f2.setVisible(true);
        f3.setVisible(false);
        f4.setVisible(false);
        f5.setVisible(false);
        f6.setVisible(false);
    
        //f2的设计
        b2 = new JButton("基本测试");
        b3 = new JButton("双重加解密");
        b4 = new JButton("中间相遇攻击");
        b10 = new JButton("三重加解密");
        b11 = new JButton("工作模式");
        listener2 = new action2();
        listener3 = new action3();
        listener4 = new action4();
        listener10 = new action10();
        listener11 = new action11();
        b2.addActionListener(listener2);
        b3.addActionListener(listener3);
        b4.addActionListener(listener4);
        b10.addActionListener(listener10);
        b11.addActionListener(listener11);
        f2.add(b2);
        f2.add(b3);
        f2.add(b4);
        f2.add(b10);
        f2.add(b11);
    
        //f1的设计
        b1 = new JButton("加密");
        b12 = new JButton("解密");
        b7 = new JButton("返回");
        listener1 = new action1();
        b1.addActionListener(listener1);
        listener12 = new action12();
        b12.addActionListener(listener12);
        listener7 = new action7();
        b7.addActionListener(listener7);
        text1 = new JTextField(10);
        text2 = new JTextField(10);
        listener1.setJTextField1(text1);
        listener1.setJTextField2(text2);
        listener12.setJTextField1(text1);
        listener12.setJTextField2(text2);
        text1.addActionListener(listener1);
        text2.addActionListener(listener1);
        text1.addActionListener(listener12);
        text2.addActionListener(listener12);
        label1 = new JLabel("请输入密钥(16位):");
        label2 = new JLabel("请输入明/密文(16位):");
        label3 = new JLabel("本次加密/解密的结果是：");
        f1.add(label1);
        f1.add(text1);
        f1.add(label2);
        f1.add(text2);
        f1.add(b1);
        f1.add(b12);
        f1.add(b7);
        f1.add(label3);
    
        //f3的设计
        b13 = new JButton("加密");
        b5 = new JButton("解密");
        b8 = new JButton("返回");
        listener13 = new action13();
        b13.addActionListener(listener13);
        listener5 = new action5();
        b5.addActionListener(listener5);
        listener8 = new action8();
        b8.addActionListener(listener8);
        text3 = new JTextField(10);
        text4 = new JTextField(10);
        listener13.setJTextField1(text3);
        listener13.setJTextField2(text4);
        listener5.setJTextField1(text3);
        listener5.setJTextField2(text4);
        text3.addActionListener(listener13);
        text4.addActionListener(listener13);
        text3.addActionListener(listener5);
        text4.addActionListener(listener5);
        label4 = new JLabel("请输入密钥(16进制输入,K1+K2):");
        label5 = new JLabel("请输入明/密文(16位):");
        label6 = new JLabel("本次加密/解密的结果是：");
        f3.add(label4);
        f3.add(text3);
        f3.add(label5);
        f3.add(text4);
        f3.add(b13);
        f3.add(b5);
        f3.add(b8);
        f3.add(label6);
    
        //f4的设计
        b6 = new JButton("开始破解");
        b9 = new JButton("返回");
        listener6 = new action6();
        b6.addActionListener(listener6);
        listener9 = new action9();
        b9.addActionListener(listener9);
        text5 = new JTextField(10);
        text6 = new JTextField(10);
        listener6.setJTextField1(text5);
        listener6.setJTextField2(text6);
        text5.addActionListener(listener6);
        text6.addActionListener(listener6);
        label7 = new JLabel("请输入明文(16位):");
        label8 = new JLabel("请输入密文(16位):");
        label9 = new JLabel("本次破解的结果是：                                        "); 
        label9.setForeground(Color.RED);
        Dimension preferredSize = new Dimension(1000, 100);
        label9.setPreferredSize(preferredSize);
        //label10 = new JLabel("破解的消耗的时间为：");
        f4.add(label7);
        f4.add(text5);
        f4.add(label8);
        f4.add(text6);
        f4.add(b6);
        f4.add(b9);
        f4.add(label9);
        //f4.add(label10);

        //f5的设计
        b14 = new JButton("加密");
        b15 = new JButton("解密");
        b16 = new JButton("返回");
        listener14 = new action14();
        b14.addActionListener(listener14);
        listener15 = new action15();
        b15.addActionListener(listener15);
        listener16 = new action16();
        b16.addActionListener(listener16);
        text7 = new JTextField(10);
        text8 = new JTextField(10);
        listener14.setJTextField1(text7);
        listener14.setJTextField2(text8);
        listener15.setJTextField1(text7);
        listener15.setJTextField2(text8);
        text7.addActionListener(listener14);
        text8.addActionListener(listener14);
        text7.addActionListener(listener15);
        text8.addActionListener(listener15);
        label10 = new JLabel("请输入密钥(16进制输入,K1+K2):");
        label11 = new JLabel("请输入密文(16位):");
        label12 = new JLabel("本次解密的结果是：");
        f5.add(label10);
        f5.add(text7);
        f5.add(label11);
        f5.add(text8);
        f5.add(b14);
        f5.add(b15);
        f5.add(b16);
        f5.add(label12);

        //f6的设计
        b17 = new JButton("加密");
        b18 = new JButton("解密");
        b19 = new JButton("返回");
        listener17 = new action17();
        b17.addActionListener(listener17);
        listener18 = new action18();
        b18.addActionListener(listener18);
        listener19 = new action19();
        b19.addActionListener(listener19);
        text9 = new JTextField(10);
        text10 = new JTextField(10);
        text11 = new JTextField(10);
        listener17.setJTextField1(text9);
        listener17.setJTextField2(text10);
        listener17.setJTextField3(text11);
        listener18.setJTextField1(text9);
        listener18.setJTextField2(text10);
        listener18.setJTextField3(text11);
        text9.addActionListener(listener17);
        text10.addActionListener(listener17);
        text11.addActionListener(listener17);
        text9.addActionListener(listener18);
        text10.addActionListener(listener18);
        text11.addActionListener(listener18);
        label13 = new JLabel("请输入密钥(16位):");
        label14 = new JLabel("请输入明/密文(ASCII码形式):");
        label15 = new JLabel("本次加/解密的结果是：");
        label16 = new JLabel("请输入初始向量(16位):");
        f6.add(label13);
        f6.add(text9);
        f6.add(label14);
        f6.add(text10);
        f6.add(label16);
        f6.add(text11);
        f6.add(b17);
        f6.add(b18);
        f6.add(b19);
        f6.add(label15);
    }
    
    public interface myListener extends ActionListener{
        public void setJTextField1(JTextField text);
        public void setJTextField2(JTextField text);
    }

    public interface anotherListener extends ActionListener{
        public void setJTextField1(JTextField text);
        public void setJTextField2(JTextField text);
        public void setJTextField3(JTextField text);
    }

    public class action1 implements myListener{
        JTextField textInput1;
        JTextField textInput2;
        public void setJTextField1(JTextField text){
            textInput1 = text;
        }
        public void setJTextField2(JTextField text){
            textInput2 = text;
        }
        public void actionPerformed(java.awt.event.ActionEvent e){
            String s1 = textInput1.getText();
            String s2 = textInput2.getText();
            if(s1.length()!=16||s2.length()!=16){
                JOptionPane.showMessageDialog(f1,"请重新输入", "输入格式有误！", JOptionPane.WARNING_MESSAGE);
            }
            else{
                boolean flag = true;
                for(int i = 0; i<s1.length(); i++){
                    if(s1.substring(i, i+1).equals("0")||s1.substring(i, i+1).equals("1")){}
                    else{
                        JOptionPane.showMessageDialog(f1,"请重新输入", "输入格式有误！", JOptionPane.WARNING_MESSAGE);
                        flag = false;
                        break;
                    }
                }
                if(flag){
                    String ciphertext;
                    ciphertext = encrypt(s2, s1);
                    label3.setText("本次加密的结果是："+ciphertext);
                }
            }
        }
    }

        public class action2 implements ActionListener{
            public void actionPerformed(java.awt.event.ActionEvent e){
                f2.setVisible(false);
                f1.setVisible(true);
            }
        }
    
        public class action3 implements ActionListener{
            public void actionPerformed(java.awt.event.ActionEvent e){
                f2.setVisible(false);
                f3.setVisible(true);
            }
        }
    
        public class action4 implements ActionListener{
            public void actionPerformed(java.awt.event.ActionEvent e){
                f2.setVisible(false);
                f4.setVisible(true);
            }
        }
    
        public class action5 implements myListener{
            JTextField textInput1;
            JTextField textInput2;
            public void setJTextField1(JTextField text){
                textInput1 = text;
            }
            public void setJTextField2(JTextField text){
                textInput2 = text;
            }
            public void actionPerformed(java.awt.event.ActionEvent e){
                String s1 = textInput1.getText();
                String s2 = textInput2.getText();
                // if(s1.length()!=32||s2.length()!=16){
                //     JOptionPane.showMessageDialog(f3,"请重新输入", "输入格式有误！", JOptionPane.WARNING_MESSAGE);
                // }
                // else{
                //     boolean flag = true;
                //     for(int i = 0; i<s1.length(); i++){
                //         if(s1.substring(i, i+1).equals("0")||s1.substring(i, i+1).equals("1")){}
                //         else{
                //             JOptionPane.showMessageDialog(f3,"请重新输入", "输入格式有误！", JOptionPane.WARNING_MESSAGE);
                //             flag = false;
                //             break;
                //         }
                //     }
                //     if(flag){
                        String plaintext;
                        plaintext = doudecrypt(s1, s2);
                        label6.setText("本次解密的结果是："+plaintext);
                    }
            //     }
            // }
        }
    
        public class action6 implements myListener{
            JTextField textInput1;
            JTextField textInput2;
            public void setJTextField1(JTextField text){
                textInput1 = text;
            }
            public void setJTextField2(JTextField text){
                textInput2 = text;
            }
            public void actionPerformed(java.awt.event.ActionEvent e){
                String s1 = textInput1.getText();
                String s2 = textInput2.getText();
                if(s1.length()!=16||s2.length()!=16){
                    JOptionPane.showMessageDialog(f4,"请重新输入", "密文或明文格式错误！", JOptionPane.WARNING_MESSAGE);
                }
                else{
                    boolean flag = true;
                    for(int i = 0; i<s1.length(); i++){
                        if(s1.substring(i, i+1).equals("0")||s1.substring(i, i+1).equals("1")){}
                        else{
                            JOptionPane.showMessageDialog(f4,"请重新输入", "密文或明文格式错误！", JOptionPane.WARNING_MESSAGE);
                            flag = false;
                            break;
                        }
                    }
                    if(flag){
                        //long startTime = System.nanoTime();
                        ArrayList<String> key = new ArrayList<String>();
                        key = zhongjian(s1, s2);
                        //long endTime = System.nanoTime();
                        //long duration = endTime - startTime;
                        //double milliseconds = (double) duration / 1_000_000.0;
                        String text1 = "";
                        for (String str : key) {
                            text1=text1+str.substring(0,16)+"和"+str.substring(16)+",      ";
                        }
                        label9.setText("一共破解出"+key.size()+"个密钥对，破解的结果是："+text1);
                        //label10.setText("破解的消耗的时间为："+milliseconds+" 毫秒");
                    }
                }
            }
        }
    
        public class action7 implements ActionListener{
            public void actionPerformed(java.awt.event.ActionEvent e){
                f1.setVisible(false);
                f2.setVisible(true);
            }
        }
    
        public class action8 implements ActionListener{
            public void actionPerformed(java.awt.event.ActionEvent e){
                f3.setVisible(false);
                f2.setVisible(true);
            }
        }
    
        public class action9 implements ActionListener{
            public void actionPerformed(java.awt.event.ActionEvent e){
                f4.setVisible(false);
                f2.setVisible(true);
            }
        }
    
        public class action10 implements ActionListener{
            public void actionPerformed(java.awt.event.ActionEvent e){
                f2.setVisible(false);
                f5.setVisible(true);
            }
        }

        public class action11 implements ActionListener{
            public void actionPerformed(java.awt.event.ActionEvent e){
                f2.setVisible(false);
                f6.setVisible(true);
            }
        }

        public class action12 implements myListener{
            JTextField textInput1;
            JTextField textInput2;
            public void setJTextField1(JTextField text){
                textInput1 = text;
            }
            public void setJTextField2(JTextField text){
                textInput2 = text;
            }
            public void actionPerformed(java.awt.event.ActionEvent e){
                String s1 = textInput1.getText();
                String s2 = textInput2.getText();
                if(s1.length()!=16||s2.length()!=16){
                    JOptionPane.showMessageDialog(f1,"请重新输入", "输入格式有误！", JOptionPane.WARNING_MESSAGE);
                }
                else{
                    boolean flag = true;
                    for(int i = 0; i<s1.length(); i++){
                        if(s1.substring(i, i+1).equals("0")||s1.substring(i, i+1).equals("1")){}
                        else{
                            JOptionPane.showMessageDialog(f1,"请重新输入", "输入格式有误！", JOptionPane.WARNING_MESSAGE);
                            flag = false;
                            break;
                        }
                    }
                    if(flag){
                        String plaintext;
                        plaintext = decrypt(s2, s1);
                        label3.setText("本次解密的结果是："+plaintext);
                    }
                }
            }
        }

    public class action13 implements myListener{
        JTextField textInput1;
        JTextField textInput2;
        public void setJTextField1(JTextField text){
            textInput1 = text;
        }
        public void setJTextField2(JTextField text){
            textInput2 = text;
        }
        public void actionPerformed(java.awt.event.ActionEvent e){
            String s1 = textInput1.getText();
            String s2 = textInput2.getText();
            if(s1.length()!=8||s2.length()!=16){
                JOptionPane.showMessageDialog(f3,"请重新输入", "输入格式有误！", JOptionPane.WARNING_MESSAGE);
            }
            else{
                boolean flag = true;
                for(int i = 0; i<s2.length(); i++){
                    if(s2.substring(i, i+1).equals("0")||s2.substring(i, i+1).equals("1")){}
                    else{
                        JOptionPane.showMessageDialog(f3,"请重新输入", "输入格式有误！", JOptionPane.WARNING_MESSAGE);
                        flag = false;
                        break;
                    }
                }
                if(flag){
                    String ciphertext;
                    ciphertext = douencrypt(s1, s2);
                    label6.setText("本次加密的结果是："+ciphertext);
                }
            }
        }
    }

    public class action14 implements myListener{
        JTextField textInput1;
        JTextField textInput2;
        public void setJTextField1(JTextField text){
            textInput1 = text;
        }
        public void setJTextField2(JTextField text){
            textInput2 = text;
        }
        public void actionPerformed(java.awt.event.ActionEvent e){
            String s1 = textInput1.getText();
            String s2 = textInput2.getText();
            if(s1.length()!=8||s2.length()!=16){
                JOptionPane.showMessageDialog(f5,"请重新输入", "输入格式有误！", JOptionPane.WARNING_MESSAGE);
            }
            else{
                boolean flag = true;
                for(int i = 0; i<s2.length(); i++){
                    if(s2.substring(i, i+1).equals("0")||s2.substring(i, i+1).equals("1")){}
                    else{
                        JOptionPane.showMessageDialog(f5,"请重新输入", "输入格式有误！", JOptionPane.WARNING_MESSAGE);
                        flag = false;
                        break;
                    }
                }
                if(flag){
                    String ciphertext;
                    ciphertext = triencrypt(s1, s2);
                    label12.setText("本次加密的结果是："+ciphertext);
                }
            }
        }
    }

    public class action15 implements myListener{
            JTextField textInput1;
            JTextField textInput2;
            public void setJTextField1(JTextField text){
                textInput1 = text;
            }
            public void setJTextField2(JTextField text){
                textInput2 = text;
            }
            public void actionPerformed(java.awt.event.ActionEvent e){
                String s1 = textInput1.getText();
                String s2 = textInput2.getText();
                if(s1.length()!=8||s2.length()!=16){
                    JOptionPane.showMessageDialog(f5,"请重新输入", "输入格式有误！", JOptionPane.WARNING_MESSAGE);
                }
                else{
                    boolean flag = true;
                    for(int i = 0; i<s2.length(); i++){
                        if(s2.substring(i, i+1).equals("0")||s2.substring(i, i+1).equals("1")){}
                        else{
                            JOptionPane.showMessageDialog(f5,"请重新输入", "输入格式有误！", JOptionPane.WARNING_MESSAGE);
                            flag = false;
                            break;
                        }
                    }
                    if(flag){
                        String plaintext;
                        plaintext = tridecrypt(s1, s2);
                        label12.setText("本次解密的结果是："+plaintext);
                    }
                }
            }
    }

    public class action16 implements ActionListener{
            public void actionPerformed(java.awt.event.ActionEvent e){
                f5.setVisible(false);
                f2.setVisible(true);
            }
    }

    public class action17 implements anotherListener{
        JTextField textInput1;
        JTextField textInput2;
        JTextField textInput3;
        public void setJTextField1(JTextField text){
            textInput1 = text;
        }
        public void setJTextField2(JTextField text){
            textInput2 = text;
        }
        public void setJTextField3(JTextField text){
            textInput3 = text;
        }
        public void actionPerformed(java.awt.event.ActionEvent e){
            String s1 = textInput1.getText();
            String s2 = textInput2.getText();
            String s3 = textInput3.getText();
            String ciphertext;
            ciphertext = encryptCBC(s2, s1,s3);
            label15.setText("本次加密的结果是："+ciphertext);
            }
    }

    public class action18 implements anotherListener{
        JTextField textInput1;
        JTextField textInput2;
        JTextField textInput3;
        public void setJTextField1(JTextField text){
            textInput1 = text;
        }
        public void setJTextField2(JTextField text){
            textInput2 = text;
        }
        public void setJTextField3(JTextField text){
            textInput3 = text;
        }
        public void actionPerformed(java.awt.event.ActionEvent e){
            String s1 = textInput1.getText();
            String s2 = textInput2.getText();
            String s3 = textInput3.getText();              
            String plaintext;
            plaintext = decryptCBC(s2, s1,s3);
            label15.setText("本次解密的结果是："+plaintext);
        }
    }

    public class action19 implements ActionListener{
            public void actionPerformed(java.awt.event.ActionEvent e){
                f6.setVisible(false);
                f2.setVisible(true);
            }
    }
}
