package com.driverscanner.controller;

import com.driverscanner.service.ElevationService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/elevation")
public class ElevationController {

    private final ElevationService elevation;

    public ElevationController(ElevationService elevation) {
        this.elevation = elevation;
    }

    @GetMapping
    public Map<String, Boolean> status() {
        return Map.of("elevated", elevation.isElevated());
    }
}
