<?php

    namespace App\Http\Controllers;

    use Illuminate\Http\Request;
    use App\Services\ExcelImportService;
    use App\Models\{GuaranteeSize, PriceMatrix};
    use Illuminate\Support\Facades\Storage;

    class ExcelImportController extends Controller {
        private $importService;

        public function __construct( ExcelImportService $importService ) {
            $this->importService = $importService;
        }

        public function index() {
            $stats = [
                'guarantee_amigo' => GuaranteeSize::where( 'brand', 'АМИГО' )->count(),
                'guarantee_forum' => GuaranteeSize::where( 'brand', 'ФОРУМ' )->count(),
                'price_matrix' => PriceMatrix::count(),
            ];

            return view( 'excel-import.index', compact( 'stats' ) );
        }

        public function import( Request $request ) {
            $request->validate( [
                'file' => 'required|file|mimes:xlsx,xls|max:10240',
                'import_type' => 'required|in:guarantee_amigo,guarantee_forum,price_matrix',
            ] );

            try {
                $file = $request->file( 'file' );
                $path = $file->store( 'temp_imports' );
                $fullPath = Storage::path( $path );

                $result = $this->importService->import(
                    $fullPath,
                    $request->import_type,
                    $file->getClientOriginalName()
                );

                Storage::delete( $path );

                if( $result[ 'success' ] ) {
                    $message = "Успешно импортировано {$result['success_count']} записей.";

                    if( !empty( $result[ 'errors' ] ) ) {
                        session()->flash( 'warnings', $result[ 'errors' ] );
                    }

                    return back()->with( 'success', $message );
                } else {
                    return back()->with( 'error', 'Не удалось импортировать данные: ' . implode( ', ', $result[ 'errors' ] ) );
                }

            } catch( \Exception $e ) {
                return back()->with( 'error', 'Ошибка импорта: ' . $e->getMessage() );
            }
        }

        public function clear( Request $request ) {
            $type = $request->get( 'type' );

            switch( $type ) {
                case 'guarantee_amigo':
                    GuaranteeSize::where( 'brand', 'АМИГО' )->delete();
                    break;
                case 'guarantee_forum':
                    GuaranteeSize::where( 'brand', 'ФОРУМ' )->delete();
                    break;
                case 'price_matrix':
                    PriceMatrix::truncate();
                    break;
                default:
                    return back()->with( 'error', 'Неизвестный тип' );
            }

            return back()->with( 'success', 'Данные успешно удалены' );
        }

        public function export( Request $request ) {
            $type = $request->get( 'type' );

            switch( $type ) {
                case 'guarantee_amigo':
                    $data = GuaranteeSize::where( 'brand', 'АМИГО' )->get();
                    break;
                case 'guarantee_forum':
                    $data = GuaranteeSize::where( 'brand', 'ФОРУМ' )->get();
                    break;
                case 'price_matrix':
                    $data = PriceMatrix::all();
                    break;
                default:
                    return response()->json( [ 'error' => 'Неизвестный тип' ], 400 );
            }

            return response()->json( $data );
        }
    }
