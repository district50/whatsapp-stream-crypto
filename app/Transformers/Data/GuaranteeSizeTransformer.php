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
            'pt' => $model->product_type,
            'br' => $model->brand,
            'fn' => $model->fabric_name,
            'wn' => $model->width_min,
            'wx' => $model->width_max,
            'hn' => $model->height_min,
            'hx' => $model->height_max,
        ];
    }

}
