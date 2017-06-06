package com.rtmap.util;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.*;

/**
 * Created by huzongtao on 2016/12/8.
 */
public class SignUtil {
    private static final String CHARSET = "UTF-8";

    public SignUtil() {
    }


    //验证签名
    public static boolean checkMapSign(Map<String, Object> resultMap, String key) {
        Object signFromAPIResponse = resultMap.get("sign");
        if(signFromAPIResponse != null && !signFromAPIResponse.equals("")) {
            resultMap.put("sign", "");
            String signForAPIResponse = getMapSign(resultMap, key);
            return signForAPIResponse.equals(signFromAPIResponse);
        } else {
            return false;
        }
    }

    //生成签名
    public static String getMapSign(Map<String, Object> map, String key) {
        map.remove("sign");
        ArrayList list = new ArrayList();
        Iterator size = map.entrySet().iterator();

        while(size.hasNext()) {
            Map.Entry arrayToSort = (Map.Entry)size.next();
            if(arrayToSort.getValue() != null && !arrayToSort.getValue().equals("")) {
                list.add((String)arrayToSort.getKey() + "=" + arrayToSort.getValue() + "&");
            }
        }

        int var7 = list.size();
        String[] var8 = (String[])list.toArray(new String[var7]);
        Arrays.sort(var8, String.CASE_INSENSITIVE_ORDER);
        StringBuilder sb = new StringBuilder();

        for(int result = 0; result < var7; ++result) {
            sb.append(var8[result]);
        }

        String var9 = sb.toString();
        var9 = var9 + "key=" + key;
        var9 = MD5Utils.getMD5String(var9).toUpperCase();
        return var9;
    }


}
