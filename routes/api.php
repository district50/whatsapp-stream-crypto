<?php

    use App\Http\Controllers\Api\{PingController, v1\Data\DataController};
    use Illuminate\Support\Facades\Route;

    Route::get( '/ping', [ PingController::class, 'index' ] )->name( 'index' );

    Route::prefix( 'v1' )->group( function() {
        // справочники
        Route::prefix( 'data' )->name( 'data.' )->group( function() {
            Route::get( '/guarantee-size', [ DataController::class, 'guaranteeSize' ] )->name( 'guaranteeSize' );
            Route::get( '/price-matrix', [ DataController::class, 'priceMatrix' ] )->name( 'priceMatrix' );
        } );
    } );
