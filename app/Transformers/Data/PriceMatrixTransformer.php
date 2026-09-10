<?php

namespace App\Transformers\Data;

use App\Models\PriceMatrix;
use League\Fractal\TransformerAbstract;

class PriceMatrixTransformer extends TransformerAbstract {
    protected array $defaultIncludes = [

    ];

    protected array $availableIncludes = [

    ];

    public function transform(PriceMatrix $model): array {
        return [
            'id' => $model->id,
            'product_type' => $model->product_type,
            'calculate_type' => $model->calculate_type,
            'width_value' => $model->width_value,
            'height_value' => $model->height_value,
            'price' => $model->price,
        ];
    }

}
