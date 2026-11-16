package com.ex;

import org.springframework.web.bind.annotation.*;

@RestController
public class ShopController {
    @GetMapping("/products/{id}")
    public String product(@PathVariable Long id) { return ""; }

    @PostMapping("/products")
    public String create() { return ""; }

    @DeleteMapping("/admin/users/{id}")
    public void drop(@PathVariable Long id) { }
}
