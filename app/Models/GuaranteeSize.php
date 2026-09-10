<?php

    namespace App\Models;

    use Illuminate\Database\Eloquent\Model;

    class GuaranteeSize extends Model {
        protected $fillable = [
            'product_type',
            'brand',
            'item_number',
            'fabric_name',
            'category',
            'width_min',
            'width_max',
            'height_min',
            'height_max',
            'width_min_alt',
            'width_max_alt',
            'height_min_alt',
            'height_max_alt',
            'notes',
            'fabric_width',
        ];

        protected $casts = [
            'width_min' => 'integer',
            'width_max' => 'integer',
            'height_min' => 'integer',
            'height_max' => 'integer',
            'width_min_alt' => 'integer',
            'width_max_alt' => 'integer',
            'height_min_alt' => 'integer',
            'height_max_alt' => 'integer',
        ];

        public function getWidthRangeAttribute() {
            if( $this->width_min && $this->width_max ) {
                return $this->width_min . '/' . $this->width_max . ' см';
            }
            return null;
        }

        public function getHeightRangeAttribute() {
            if( $this->height_min && $this->height_max ) {
                return $this->height_min . '/' . $this->height_max . ' см';
            }
            return null;
        }
    }
