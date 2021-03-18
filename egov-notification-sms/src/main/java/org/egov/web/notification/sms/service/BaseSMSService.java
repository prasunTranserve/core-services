package org.egov.web.notification.sms.service;

import java.io.IOException;
import java.lang.reflect.Type;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.net.ssl.SSLContext;

import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.egov.web.notification.sms.config.SMSProperties;
import org.egov.web.notification.sms.models.Sms;
import org.egov.web.notification.sms.service.impl.SMSServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import lombok.extern.slf4j.Slf4j;

@Slf4j
abstract public class BaseSMSService implements SMSService, SMSBodyBuilder {

	private static final String SMS_RESPONSE_NOT_SUCCESSFUL = "Sms response not successful";

	@Autowired
	protected RestTemplate restTemplate;

	@Autowired
	protected SMSProperties smsProperties;

	@Autowired
	protected Environment env;

	@Autowired
	protected SMSServices smsServices;

	@PostConstruct
	public void init() {
		List<HttpMessageConverter<?>> converters = restTemplate.getMessageConverters();
		converters.remove(converters.stream()
				.filter(c -> c.getClass().equals(MappingJackson2HttpMessageConverter.class)).findFirst().get());
		converters.add(new MappingJackson2HttpMessageConverter() {
			@Override
			protected void writeInternal(Object object, Type type, HttpOutputMessage outputMessage)
					throws IOException, HttpMessageNotWritableException {
				if (object.getClass().equals(LinkedMultiValueMap.class)) {
					LinkedMultiValueMap<?, ?> map = (LinkedMultiValueMap<?, ?>) object;
					object = map.toSingleValueMap();
				}
				super.writeInternal(object, type, outputMessage);
			}
		});
	}

	@Override
	public void sendSMS(Sms sms) {
		if (!sms.isValid()) {
			log.error(String.format("Sms %s is not valid", sms));
			return;
		}

		if (smsProperties.isNumberBlacklisted(sms.getMobileNumber())) {
			log.error(String.format("Sms to %s is blacklisted", sms.getMobileNumber()));
			return;
		}

		if (!smsProperties.isNumberWhitelisted(sms.getMobileNumber())) {
			log.error(String.format("Sms to %s is not in whitelist", sms.getMobileNumber()));
			return;
		}

		String userName = smsProperties.getUsername();
		String password = smsProperties.getPassword();
		String senderID = smsProperties.getSenderid();
		String secureKey = smsProperties.getSecureKey();
		String url = smsProperties.getUrl();
		String message = sms.getMessage();
		String mobileNumber = sms.getMobileNumber();

		smsServices.sendSingleSMS(userName, password, message, senderID, mobileNumber, secureKey);

		// submitToExternalSmsService(sms);
	}

	protected abstract void submitToExternalSmsService(Sms sms);

	protected <T> ResponseEntity<T> executeAPI(URI uri, HttpMethod method, HttpEntity<?> requestEntity, Class<T> type) {
		ResponseEntity<T> res = (ResponseEntity<T>) restTemplate.exchange(uri, method, requestEntity, String.class);
		String responseString = res.getBody().toString();
		if (!isResponseValidated(res)) {
			log.error("Response from API - " + responseString);
			throw new RuntimeException(SMS_RESPONSE_NOT_SUCCESSFUL);
		}

		if (smsProperties.getSmsErrorCodes().size() > 0 && isResponseCodeInKnownErrorCodeList(res)) {
			throw new RuntimeException(SMS_RESPONSE_NOT_SUCCESSFUL);
		}

		if (smsProperties.getSmsSuccessCodes().size() > 0 && !isResponseCodeInKnownSuccessCodeList(res)) {
			throw new RuntimeException(SMS_RESPONSE_NOT_SUCCESSFUL);
		}

		return res;
	}

	protected boolean isResponseValidated(ResponseEntity<?> response) {
		String responseString = response.getBody().toString();
		if (smsProperties.isVerifyResponse() && !responseString.contains(smsProperties.getVerifyResponseContains())) {
			return false;
		}
		return true;
	}

	protected boolean isResponseCodeInKnownErrorCodeList(ResponseEntity<?> response) {
		final String responseCode = Integer.toString(response.getStatusCodeValue());
		return smsProperties.getSmsErrorCodes().stream().anyMatch(errorCode -> errorCode.equals(responseCode));
	}

	protected boolean isResponseCodeInKnownSuccessCodeList(ResponseEntity<?> response) {
		final String responseCode = Integer.toString(response.getStatusCodeValue());
		return smsProperties.getSmsSuccessCodes().stream().anyMatch(successCode -> successCode.equals(responseCode));
	}

	public MultiValueMap<String, String> getSmsRequestBody(Sms sms) {
		MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		for (String key : smsProperties.getConfigMap().keySet()) {
			String value = smsProperties.getConfigMap().get(key);
			if (value.startsWith("$")) {
				switch (value) {
				case "$username":
					map.add(key, smsProperties.getUsername());
					break;
				case "$password":
					map.add(key, smsProperties.getPassword());
					break;
				case "$senderid":
					map.add(key, smsProperties.getSenderid());
					break;
				case "$mobileno":
					map.add(key, smsProperties.getMobileNumberPrefix() + sms.getMobileNumber());
					break;
				case "$message":
					map.add(key, sms.getMessage());
					break;
				default:
					if (env.containsProperty(value.substring(1))) {
						map.add(key, env.getProperty(value.substring(1)));
					} else if (smsProperties.getExtraConfigMap().containsKey(value.substring(1))) {
						map.add(key, smsProperties.getExtraConfigMap().get(value.substring(1)));
					} else if (smsProperties.getCategoryMap().containsKey(value.substring(1))) {
						Map<String, Map<String, String>> categoryMap = smsProperties.getCategoryMap();
						Map<String, String> categoryValue = categoryMap.get(value.substring(1));
						if (sms.getCategory() == null && categoryValue.containsKey('*')) {
							map.add(key, categoryValue.get('*'));
						} else if (sms.getCategory() != null) {
							if (categoryValue.containsKey(sms.getCategory().toString())) {
								map.add(key, categoryValue.get(sms.getCategory().toString()));
							} else if (categoryValue.containsKey('*')) {
								map.add(key, categoryValue.get('*'));
							}
						}
					} else {
						map.add(key, value);
					}
					break;
				}
			} else {
				map.add(key, value);
			}

		}

		return map;
	}

	protected HttpEntity<MultiValueMap<String, String>> getRequest(Sms sms) {
		final MultiValueMap<String, String> requestBody = getSmsRequestBody(sms);
		return new HttpEntity<>(requestBody, getHttpHeaders());
	}

	protected HttpHeaders getHttpHeaders() {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.valueOf(smsProperties.getContentType()));
		return headers;
	}

	@PostConstruct
	protected void setupSSL() {
		if (!smsProperties.isVerifySSL()) {
			TrustStrategy acceptingTrustStrategy = new TrustStrategy() {
				@Override
				public boolean isTrusted(java.security.cert.X509Certificate[] x509Certificates, String s) {
					return true;
				}

			};

			SSLContext sslContext = null;
			try {
				sslContext = org.apache.http.ssl.SSLContexts.custom().loadTrustMaterial(null, acceptingTrustStrategy)
						.build();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (KeyManagementException e) {
				e.printStackTrace();
			} catch (KeyStoreException e) {
				e.printStackTrace();
			}
			SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, new NoopHostnameVerifier());
			CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(csf).build();
			HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
			requestFactory.setHttpClient(httpClient);
			restTemplate.setRequestFactory(requestFactory);
		}
	}

}
