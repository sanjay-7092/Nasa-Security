package com.nasa.security.service;

import com.nasa.security.models.UserToken;

public interface UserTokenService {

    public UserToken getByUserName(String userName);
}
