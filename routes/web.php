<?php

    use Illuminate\Support\Facades\Route;
    use App\Http\Controllers\ExcelImportController;

    Route::get( '/', function() {
        return redirect()->route( 'excel-import.index' );
    } );

    Route::prefix( 'excel-import' )->name( 'excel-import.' )->group( function() {
        Route::get( '/', [ ExcelImportController::class, 'index' ] )->name( 'index' );
        Route::post( '/import', [ ExcelImportController::class, 'import' ] )->name( 'process' );
        Route::delete( '/clear', [ ExcelImportController::class, 'clear' ] )->name( 'clear' );
        Route::get( '/export', [ ExcelImportController::class, 'export' ] )->name( 'export' );
    } );
