<?php

    namespace App\Http\Controllers\Api\v1\B24;

    use App\Http\Controllers\Controller;
    use Illuminate\Http\JsonResponse;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Storage;

    class OrderController extends Controller {

        public function __construct() { }

        public function create( Request $request ): ?JsonResponse {
            Storage::disk( 'local' )->put( 'sync/order.json', json_encode( $request->all() ) );
            return new JsonResponse([
                'success' => true,
            ]);
            //return ($model = GuaranteeSize::all()) ? fractal($model, new GuaranteeSizeTransformer())->respond() : null;
        }
    }
