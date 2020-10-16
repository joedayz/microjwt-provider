package com.nabenik.jwt.auth;

public enum RolesEnum {
	USUARIO("usuario"),
	ADMIN("admin");

	private String role;

	public String getRole() {
		return this.role;
	}

	RolesEnum(String role) {
		this.role = role;
	}
}
