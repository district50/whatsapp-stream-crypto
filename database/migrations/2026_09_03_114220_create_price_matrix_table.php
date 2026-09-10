<?php

    use Illuminate\Database\Migrations\Migration;
    use Illuminate\Database\Schema\Blueprint;
    use Illuminate\Support\Facades\Schema;

    return new class extends Migration {
        public function up() {
            Schema::create( 'price_matrix', function( Blueprint $table ) {
                $table->id();
                $table->string( 'product_type' )->default( 'МИНИ' );
                $table->string( 'calculation_type' ); // 'width' или 'height'
                $table->string( 'category' );
                $table->decimal( 'width_value', 4, 1 );
                $table->decimal( 'height_value', 4, 1 );
                $table->integer( 'price' );
                $table->text( 'notes' )->nullable();
                $table->timestamps();

                $table->index( [ 'product_type', 'calculation_type', 'category' ] );
                $table->index( [ 'width_value', 'height_value' ] );
            } );
        }

        public function down() {
            Schema::dropIfExists( 'price_matrix' );
        }
    };
