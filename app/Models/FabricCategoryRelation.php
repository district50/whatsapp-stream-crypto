<?php

    namespace App\Models;

    use Illuminate\Database\Eloquent\Model;

    class FabricCategoryRelation extends Model {
        protected $fillable = [
            'fabric_name',
            'category_code',
            'product_type',
            'brand',
            'is_active',
        ];

        protected $casts = [
            'is_active' => 'boolean',
        ];
    }
