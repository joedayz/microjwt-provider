package com.nabenik.jwt.dto;

import java.io.Serializable;

public class TokenResponse  implements Serializable {

	private static final long serialVersionUID = 1L;

	private String token;

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}
}
