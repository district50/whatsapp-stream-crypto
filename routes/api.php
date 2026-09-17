<?php

    use App\Http\Controllers\Api\PingController;
    use App\Http\Controllers\Api\v1\B24\{OrderController};
    use App\Http\Controllers\Api\v1\{Data\DataController, Sync\SyncController};
    use Illuminate\Support\Facades\Route;

    Route::get( '/ping', [ PingController::class, 'index' ] )->name( 'index' );

    Route::prefix( 'v1' )->name( 'v1.' )->group( function() {
        // справочники
        Route::prefix( 'data' )->name( 'data.' )->group( function() {
            Route::get( '/guarantee-size', [ DataController::class, 'guaranteeSize' ] )->name( 'guaranteeSize' );
            Route::get( '/price-matrix', [ DataController::class, 'priceMatrix' ] )->name( 'priceMatrix' );
        } );
        // синхронизация информации
        Route::prefix( 'sync' )->name( 'sync.' )->group( function() {
            Route::post( '/measurements', [ SyncController::class, 'measurements' ] )->name( 'measurements' );
        } );
        // Bitrix24
        Route::prefix( 'b24' )->name( 'b24.' )->group( function() {
            Route::prefix( 'order' )->name( 'order.' )->group( function() {
                Route::post( '/', [ OrderController::class, 'create' ] )->name( 'create' );
            } );
        } );
    } );
