<?php

    namespace App\Models;

    use Illuminate\Database\Eloquent\Model;

    class ProductType extends Model {
        protected $fillable = [
            'code',
            'name',
            'brand',
            'description',
            'min_motorization_width',
            'max_height_width_ratio',
            'is_active',
        ];

        protected $casts = [
            'is_active' => 'boolean',
            'min_motorization_width' => 'integer',
            'max_height_width_ratio' => 'integer',
        ];
    }
