package com.doyeon.puppy.member.enums;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum MemberRole {
    MEMBER("MEMBER" , "MEMBER"),
    ADMIN("ADMIN", "MEMBER , ADMIN");

    public final String roleName;
    public final String roleList;
}
