package com.example.shop;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/orders")
public class OrderController {
    private final OrderRepository orders;

    public OrderController(OrderRepository orders) {
        this.orders = orders;
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('USER')")
    public Order get(@PathVariable Long id) {
        return orders.findById(id).orElseThrow();
    }

    @PostMapping
    public Order create(@RequestBody Order order) {
        return orders.save(order);
    }
}
