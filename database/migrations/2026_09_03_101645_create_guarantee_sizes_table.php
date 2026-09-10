<?php

    use Illuminate\Database\Migrations\Migration;
    use Illuminate\Database\Schema\Blueprint;
    use Illuminate\Support\Facades\Schema;

    return new class extends Migration {
        public function up() {
            Schema::create( 'guarantee_sizes', function( Blueprint $table ) {
                $table->id();
                $table->string( 'product_type' ); // МИНИ, УНИ 1, УНИ 2, MG, LVT 32, LVT 45, МАКСИ 38, МИДЛ 25
                $table->string( 'brand' ); // ФОРУМ или АМИГО
                $table->integer( 'item_number' )->nullable();
                $table->string( 'fabric_name' );
                $table->string( 'category' );

                // Основные размеры (раскрой по ширине)
                $table->integer( 'width_min' )->nullable();
                $table->integer( 'width_max' )->nullable();
                $table->integer( 'height_min' )->nullable();
                $table->integer( 'height_max' )->nullable();

                // Альтернативные размеры (раскрой по высоте) - для ФОРУМ
                $table->integer( 'width_min_alt' )->nullable();
                $table->integer( 'width_max_alt' )->nullable();
                $table->integer( 'height_min_alt' )->nullable();
                $table->integer( 'height_max_alt' )->nullable();

                $table->text( 'notes' )->nullable();
                $table->string( 'fabric_width' )->nullable(); // 200см, 250см и т.д.
                $table->timestamps();

                $table->index( [ 'product_type', 'brand' ] );
                $table->index( 'category' );
                $table->index( 'fabric_name' );
            } );
        }

        public function down() {
            Schema::dropIfExists( 'guarantee_sizes' );
        }
    };
