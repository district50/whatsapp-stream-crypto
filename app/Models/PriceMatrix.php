<?php

    namespace App\Models;

    use Illuminate\Database\Eloquent\Model;

    class PriceMatrix extends Model {
        protected $table = 'price_matrix';

        protected $fillable = [
            'product_type',
            'calculation_type',
            'category',
            'width_value',
            'height_value',
            'price',
            'notes',
        ];

        protected $casts = [
            'width_value' => 'float',
            'height_value' => 'float',
            'price' => 'integer',
        ];

        public function scopeByCategory( $query, $category ) {
            return $query->where( 'category', $category );
        }

        public function scopeByCalculationType( $query, $type ) {
            return $query->where( 'calculation_type', $type );
        }
    }
