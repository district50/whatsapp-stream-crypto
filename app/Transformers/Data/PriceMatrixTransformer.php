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
            'pt' => $model->product_type,
            'ct' => $model->calculate_type,
            'wv' => $model->width_value,
            'hv' => $model->height_value,
            'pr' => $model->price,
        ];
    }

}
