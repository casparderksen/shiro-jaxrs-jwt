package org.apache.shiro.jwt;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum Claims {

    upn("MP-JWT specific unique principal name"),
    groups("MP-JWT specific groups permission grant");

    private String description;
}
