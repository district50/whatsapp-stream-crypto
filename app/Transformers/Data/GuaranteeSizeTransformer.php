<?php

namespace App\Transformers\Data;

use App\Models\GuaranteeSize;
use League\Fractal\TransformerAbstract;

class GuaranteeSizeTransformer extends TransformerAbstract {
    protected array $defaultIncludes = [

    ];

    protected array $availableIncludes = [

    ];

    public function transform(GuaranteeSize $model): array {
        return [
            'id' => $model->id,
            'product_type'  => $model->product_type,
            'brand' => $model->brand,
            'fabric_name' => $model->fabric_name,
            'width_min' => $model->width_min,
            'width_max' => $model->width_max,
            'height_min' => $model->height_min,
            'height_max' => $model->height_max,
        ];
    }

}
