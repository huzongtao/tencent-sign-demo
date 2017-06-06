/*
 * RT MAP, Home of Professional MAP
 * Copyright 2016 Bit Main Inc. and/or its affiliates and other contributors
 * as indicated by the @author tags. All rights reserved.
 * See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 */
package com.rtmap.test;

import com.rtmap.util.SignUtil;

import java.util.HashMap;
import java.util.Map;

public class SignTest
{

   public static void main(String[] args)
   {
      String key="o8z7x2sSha4sdhAClMD";
      Map<String, Object> params = new HashMap<>();
      params.put("qr_code", "011481182827150933");
      params.put("app_id","jDKTfubt8Z2jO9PoFBA");
      String newsign = SignUtil.getMapSign(params, key);//签名
      params.put("sign",newsign);
      boolean b = SignUtil.checkMapSign(params, key);
      if (!b){
          System.out.println("签名失败");
      }else{
          System.out.println("签名成功");
      }
   }
}
