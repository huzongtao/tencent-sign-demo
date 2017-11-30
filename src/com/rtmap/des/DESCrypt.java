/*
 * RT MAP, Home of Professional MAP
 * Copyright 2017 Bit Main Inc. and/or its affiliates and other contributors
 * as indicated by the @author tags. All rights reserved.
 * See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 */
package com.rtmap.des;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/**
 * DES加密/解密算法
 * @author huzongtao@rtmap.com
 * @package com.rtmap.test
 * @date 30/11/2017
 */
public class DESCrypt {
    private static SecretKeyFactory secretKeyFactory = null;
    /**
     * Cipher 的“算法/模式/填充”
     */
    static final String CIPHER = "DES/CBC/PKCS5Padding";
    static {
        try {
            // 在静态代码块中获取秘钥工厂
            secretKeyFactory = SecretKeyFactory.getInstance("DES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     *  定义常量 ，编码格式
     */
    private static final String UTF8 = "UTF-8";

    /**
     * 对象缓存的容器
     */
    static abstract class Cache {
        private final Map<Object, Object> innerCache = new HashMap<>();

        /**
         * 对象缓存的抽象方法
         * @param key
         * @return
         * @throws Exception
         */
        protected abstract Object createValue(Object key) throws Exception;

        public Object get(Object key) throws Exception {
            Object value;
            synchronized (innerCache) {
                value = innerCache.get(key);
                if (value == null) {
                    value = new CreationPlaceholder();
                    innerCache.put(key, value);
                }
            }

            if (value instanceof CreationPlaceholder) {
                synchronized (value) {
                    CreationPlaceholder progress = (CreationPlaceholder) value;
                    if (progress.value == null) {
                        progress.value = createValue(key);
                        synchronized (innerCache) {
                            innerCache.put(key, progress.value);
                        }
                    }
                    return progress.value;
                }
            }
            return value;
        }

        static final class CreationPlaceholder {
            Object value;
        }
    }

    /**
     * str->hex 字符串转成十六进制字节数组
     * @param ss
     * @return
     */
    public static byte[] stringToHex(String ss) {
        // 字符串转化we
        byte[] digest = new byte[ss.length() / 2];
        for (int i = 0; i < digest.length; i++) {
            String byteString = ss.substring(2 * i, 2 * i + 2);
            int byteValue = Integer.parseInt(byteString, 16);
            digest[i] = (byte) byteValue;
        }
        return digest;
    }

    /**
     * hex->str 十六进制字节数组转成字符串
     * @param b
     * @return
     */
    public static String hexToString(byte[] b) {
        StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            String plainText = Integer.toHexString(0xff & b[i]);
            if (plainText.length() < 2) {
                hexString.append("0");
            }
            hexString.append(plainText);
        }

        return hexString.toString();
    }

    /**
     * 验证待加密的明文是否是8字节的倍数，如果不是8字节的倍数算法先用值为“0”的字节补足八个字节并转化为字节数组
     * 验证密钥是否为8字节的倍数
     * @param text
     * @return
     * @throws IOException
     */
    private static byte[] _convertKeyIv(String text) throws IOException {
        if (text.length() == 8) {
            return text.getBytes(UTF8);
        }
        if (text.startsWith("0x") && text.length() == 32) {
            byte[] result = new byte[8];
            for (int i = 0; i < text.length(); i += 2) {
                if (text.charAt(i++) == '0' && text.charAt(i++) == 'x') {
                    try {
                        result[i / 4] = (byte) Integer.parseInt(
                                text.substring(i, i + 2), 16);
                    } catch (Exception e) {
                        throw new IOException("TXT '" + text + "' is invalid!");
                    }
                }
            }
            return result;
        }
        throw new IOException("TXT '" + text + "' is invalid!");
    }

    /**
     * SecretKey密钥对象的缓存
     */
    private static Cache SecretKeySpecs = new Cache() {
        @Override
        protected Object createValue(Object key) throws Exception {
            SecretKey secretKeyObj = null;
            try {
                byte[] keyArray = _convertKeyIv((String) key);
                // 从原始密钥数据创建DESKeySpec对象，也就是创建秘钥的秘钥内容
                DESKeySpec desKeySpec = new DESKeySpec(keyArray);
                //密钥工厂用来将密钥（类型 Key 的不透明加密密钥）转换为密钥规范（底层密钥材料的透明表示形式），反之亦然。秘密密钥工厂只对秘密（对称）密钥进行操作。
                //根据提供的密钥规范（密钥材料）生成 SecretKey(秘钥)对象。
                secretKeyObj = secretKeyFactory.generateSecret(desKeySpec);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return secretKeyObj;
        }
    };

    /**
     * IvParameterSpec初始化向量(IV)对象的缓存
     */
    private static Cache IvParamSpecs = new Cache() {
        @Override
        protected Object createValue(Object key) throws Exception {
            IvParameterSpec ivObj;
            ivObj = new IvParameterSpec(_convertKeyIv((String) key));
            return ivObj;
        }
    };

    /**
     * 加密
     * @param text 明文
     * @param authKey 密钥
     * @param authIv
     * @return
     */
    private static String encrypt(String text, String authKey, String authIv) {
        SecretKey secretKeyObj = null;
        //他的类指定了一个初始化向量(IV)。在反馈模式中使用IV的例子是ciphers，例如在CBC模式下的DES，以及OAEP编码操作的RSA ciphers。
        IvParameterSpec ivObj = null;
        try {
            secretKeyObj = (SecretKey) SecretKeySpecs.get(authKey);
            ivObj = (IvParameterSpec) IvParamSpecs.get(authIv);
        } catch (Exception e) {
            e.printStackTrace();
        }

        byte[] data = null;
        try {
            data = text.getBytes(UTF8);
        } catch (Exception e) {
            e.printStackTrace();
        }

        byte[] authToken = null;
        try {
            authToken = encrypt(data, secretKeyObj, ivObj);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return hexToString(authToken);
    }

    private static byte[] encrypt(byte[] data, SecretKey secretKey, IvParameterSpec iv) throws Exception {
        // Cipher对象实际完成加密操作,此类为加密和解密提供密码功能
        Cipher cipher = Cipher.getInstance(CIPHER);
        //用密钥初始化此 Cipher。ENCRYPT_MODE用于将 Cipher 初始化为加密模式的常量。
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        //执行加密操作
        return cipher.doFinal(data);
    }

    /**
     * 解密
     * @param hexString 密文
     * @param authKey 密钥
     * @param authIv
     * @return
     * @throws Exception
     */
    private static String decrypt(String hexString, String authKey, String authIv)
            throws Exception {
        SecretKey secretKeyObj = null;
        IvParameterSpec ivObj = null;
        try {
            secretKeyObj = (SecretKey) SecretKeySpecs.get(authKey);
            ivObj = (IvParameterSpec) IvParamSpecs.get(authIv);
        } catch (Exception e) {
            e.printStackTrace();
        }
        byte[] data = stringToHex(hexString);
        return decrypt(data, secretKeyObj, ivObj);
    }

    private static String decrypt(byte[] data, SecretKey secretKey,
                                  IvParameterSpec iv) throws Exception {
        // Cipher对象实际完成加密操作,此类为加密和解密提供密码功能
        Cipher cipher = Cipher.getInstance(CIPHER);
        // DECRYPT_MODE用于将 Cipher 初始化为解密模式的常量。
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        // 正式进行解密操作
        byte[] retByte = cipher.doFinal(data);
        return new String(retByte);
    }

    public static void main(String[] args) throws Exception {
        long begin= System.currentTimeMillis();
        String authKey = "w8f3k9c2";
        String authIv = "w8f3k9c4";
        //String text = "aaades加密测试";
        String text = "{\n" +
                "    \"couponActivityId\": \"100\", \n" +
                "    \"couponId\": 1001,  \n" +
                "    \"openId\": \"oq1Gkt-0GjGTdRcvvS0TP70IKUWA\", \n" +
                "    \"type\": 1, \n" +
                "    \"channelId\": 1\n" +
                "}";
        // 140CB412BA03869F
        // 140cb412ba03869f

        // 对原文进行加密
        String encryptedText = encrypt(text, authKey, authIv);
        System.out.println("加密:" + encryptedText);

        // 对密文进行还原
        String plainText = decrypt(encryptedText, authKey, authIv);
        System.out.println("解密:" + plainText);
        //2a329740ce15f549be64190b183a5be2
        long end =System.currentTimeMillis();
        System.out.println("算法耗时:"+ (end-begin));
    }
}
