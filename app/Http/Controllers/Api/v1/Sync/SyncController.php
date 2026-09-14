<?php

    namespace App\Http\Controllers\Api\v1\Sync;

    use App\Http\Controllers\Controller;
    use App\Models\GuaranteeSize;
    use App\Models\PriceMatrix;
    use App\Transformers\Data\GuaranteeSizeTransformer;
    use App\Transformers\Data\PriceMatrixTransformer;
    use Illuminate\Http\JsonResponse;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Storage;

    class SyncController extends Controller {

        public function __construct() { }

        public function all( Request $request ): ?JsonResponse {
            Storage::disk( 'local' )->put( 'sync/log.json', json_encode( $request->all() ) );
            return response()->json( $request->all() );
            //return ($model = GuaranteeSize::all()) ? fractal($model, new GuaranteeSizeTransformer())->respond() : null;
        }
    }
