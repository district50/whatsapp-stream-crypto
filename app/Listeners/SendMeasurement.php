<?php

    namespace App\Listeners;

    use App\Events\NewMeasurement;
    use Illuminate\Contracts\Queue\ShouldQueue;
    use Illuminate\Queue\InteractsWithQueue;

    class SendMeasurement {
        /**
         * Create the event listener.
         */
        public function __construct() {
            //
        }

        /**
         * Handle the event.
         */
        public function handle( NewMeasurement $event ): void {
            //
        }
    }
