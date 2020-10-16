package com.nabenik.jwt.controller;

import com.nabenik.jwt.auth.CypherService;
import com.nabenik.jwt.auth.RolesEnum;
import com.nabenik.jwt.dto.BaseResponse;
import com.nabenik.jwt.dto.TokenResponse;
import com.nabenik.jwt.util.Constantes;


import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static javax.ws.rs.core.HttpHeaders.AUTHORIZATION;

@Singleton
@Path("/auth")
public class TokenProviderResource {

    @Inject
    CypherService cypherService;

    private PrivateKey key;

    @PostConstruct
    public void init() {
        try {
            key = cypherService.readPrivateKey();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public BaseResponse<TokenResponse> doPosLogin(@FormParam("username") String username, @FormParam("password")String password,
                               @Context HttpServletRequest request){

        List<String> target = new ArrayList<>();
        try {
            request.login(username, password);

            if(request.isUserInRole(RolesEnum.USUARIO.getRole()))
                target.add(RolesEnum.USUARIO.getRole());

            if(request.isUserInRole(RolesEnum.ADMIN.getRole()))
                target.add(RolesEnum.ADMIN.getRole());

        }catch (ServletException ex){
            ex.printStackTrace();
			return new BaseResponse<>(Constantes.API_ESTADO_ERROR, Constantes.MENSAJE_TOKEN_FALLIDO);
        }

        String token = cypherService.generateJWT(key, username, target);

		TokenResponse tokenResponse = new TokenResponse();
		tokenResponse.setToken(token);

		return new BaseResponse<>(Constantes.API_ESTADO_EXITO, Constantes.MENSAJE_TOKEN_EXITO,
				tokenResponse);
    }

}
