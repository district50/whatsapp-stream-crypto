<?php

    namespace App\Models;

    use Illuminate\Database\Eloquent\Model;

    class FabricCategory extends Model {
        protected $fillable = [
            'category_code',
            'category_name',
            'description',
            'is_active',
            'discount_limit',
            'commission_percent',
        ];

        protected $casts = [
            'is_active' => 'boolean',
            'discount_limit' => 'integer',
            'commission_percent' => 'integer',
        ];
    }
