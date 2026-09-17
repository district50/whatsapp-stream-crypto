<?php

    namespace App\Http\Controllers\Api\v1\Sync;

    use App\Http\Controllers\Controller;
    use App\Models\PendingSync;
    use Illuminate\Http\JsonResponse;
    use Illuminate\Http\Request;

    class SyncController extends Controller {


        protected PendingSync $model;

        public function __construct(PendingSync $model) {
            $this->model = $model;
        }

        public function measurements( Request $request ): ?JsonResponse {
//            Storage::disk( 'local' )->put( 'sync/measurements.json', json_encode( $request->all() ) );
//            $data = [
//                'entity_type' => 'measurement',
//                'payload_json' => json_encode($request->all()),
//                'status' => 'send_queue',
//            ];
//            $result = $this->model->create( $data );

            return response()->json( [
                'success' => true,
            ] );
            //return ($model = GuaranteeSize::all()) ? fractal($model, new GuaranteeSizeTransformer())->respond() : null;
        }
    }
