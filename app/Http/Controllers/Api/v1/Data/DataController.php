<?php

namespace App\Http\Controllers\Api\v1\Data;

use App\Http\Controllers\Controller;
use App\Models\GuaranteeSize;
use App\Models\PriceMatrix;
use App\Transformers\Data\GuaranteeSizeTransformer;
use App\Transformers\Data\PriceMatrixTransformer;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class DataController extends Controller {

    public function __construct() {}

    public function guaranteeSize(Request $request): ?JsonResponse {
        return ($model = GuaranteeSize::all()) ? fractal($model, new GuaranteeSizeTransformer())->respond() : null;
    }

    public function priceMatrix(Request $request): ?JsonResponse {
        return ($model = PriceMatrix::all()) ? fractal($model, new PriceMatrixTransformer())->respond() : null;
    }
}
