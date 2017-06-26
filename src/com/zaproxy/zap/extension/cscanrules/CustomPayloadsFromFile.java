package com.zaproxy.zap.extension.cscanrules;



import java.io.IOException;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.FileNotFoundException;


import java.net.UnknownHostException;

import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.ascanrules.BufferOverflow;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.network.HttpResponseBody;


public class CustomPayloadsFromFile extends AbstractAppParamPlugin {
	/**
	 * Prefix for internationalised messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "cscanrules.payloadsfromfile.";
	private static final int PLUGIN_ID =  299108;
	private static Logger log = Logger.getLogger(BufferOverflow.class);
	
	@Override
	public int getId() {
		return PLUGIN_ID;
	}

	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}

	@Override
	public String[] getDependency() {
		return null;
	}
	
	@Override
	public boolean targets(TechSet technologies) { 
		return technologies.includes(Tech.C); 
	}
	
	@Override
	public String getDescription() {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}

	@Override
	public int getCategory() {
		return Category.INJECTION;
	}

	@Override
	public String getSolution() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
	}

	@Override
	public String getReference() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}
	
	public String getOther() {
		return Constant.messages.getString(MESSAGE_PREFIX + "other");
	}
	
	@Override
	public void init() {

	}

	/*
	 * This method is called by the active scanner for each GET and POST parameter for every page 
	 * @see org.parosproxy.paros.core.scanner.AbstractAppParamPlugin#scan(org.parosproxy.paros.network.HttpMessage, java.lang.String, java.lang.String)
	 */
	@Override
	public void scan(HttpMessage msg, String param, String value) {
	
		if (this.isStop()) { // Check if the user stopped things
			if (log.isDebugEnabled()) {
				log.debug("Scanner "+this.getName()+" Stopping.");
			}
			return; // Stop!
		}
		if (getBaseMsg().getResponseHeader().getStatusCode() == HttpStatusCode.INTERNAL_SERVER_ERROR)// Check to see if the page closed initially
		{
			return;//Stop
		}
		String checkStringHeader1 = "Connection: close";  // Un natural close
		String fileName="/tmp/payloads";
		FileReader fr;
		try
		{
		fr=new FileReader(fileName);
		}
		catch (FileNotFoundException ex)
		{
			if (log.isDebugEnabled()) log.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() +  
					"\n Error opening the file"+fileName);
		return;
		}
		BufferedReader br=new BufferedReader(fr);
		String line;
		

		try {
			while((line=br.readLine())!=null)
			{
			try {
				// This is where you change the 'good' request to attack the application
				// You can make multiple requests if needed
				
				// Always use getNewMsg() for each new request
				msg = getNewMsg();
				String returnAttack = line;
				setParameter(msg, param, returnAttack);
				try {
					sendAndReceive(msg);
				} catch (UnknownHostException ex) {
					if (log.isDebugEnabled()) log.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() + 
							" when accessing: " + msg.getRequestHeader().getURI().toString() + 
							"\n The target may have replied with a poorly formed redirect due to our input.");
					return; //Something went wrong no point continuing
				}
				
				HttpResponseBody responseBody = msg.getResponseBody();	
				// This is where BASE baseResponseBody was you detect potential vulnerabilities in the response
				String chkreflectionresponse = responseBody.toString();
				log.debug("Reflection: "+ returnAttack);
				if (chkreflectionresponse.contains(returnAttack))
				{
					log.debug("Found Reflection");
					bingo(getRisk(), 
							Alert.CONFIDENCE_MEDIUM, 
							this.getBaseMsg().getRequestHeader().getURI().toString(), 
							param, 
							msg.getRequestHeader().toString(), 
							this.getOther() ,
							msg);
					return;
				}
					
					return;	
			} catch (URIException e) {
				if (log.isDebugEnabled()) {
					log.debug("Failed to send HTTP message, cause: " + e.getMessage());
				}
			} catch (IOException e) {
				log.error(e.getMessage(), e);
			}
			}
		} catch (IOException ex) {
			// TODO Auto-generated catch block
			if (log.isDebugEnabled()) log.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() +  
					"\n Error opening the buffer from "+fileName);
			return;
		}
	}

	@Override
	public int getRisk() {
		return Alert.RISK_MEDIUM;
	}

	@Override
	public int getCweId() {
		// The CWE id
		return 120;
	}

	@Override
	public int getWascId() {
		// The WASC ID
		return 7;
	}
	
	private String randomCharacterString(int length)
	{
		
		return "test";
	}
}

