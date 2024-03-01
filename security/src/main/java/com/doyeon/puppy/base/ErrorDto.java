package com.doyeon.puppy.base;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class ErrorDto {

    //    @NotNull(message = "point is not null")
    private String point;
    //   @NotNull(message = "detail is not null")
    private String detail;
}
