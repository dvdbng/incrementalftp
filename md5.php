<?php
    for($i=1;$i<=100;$i++){
        if(isset($_POST["f$i"])){
            try{
                if(file_exists($_POST["f$i"])){
                    $md = md5_file($_POST["f$i"]);
                    echo $md?$md:"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
                    echo "\n";
                }else{
                    echo "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n";
                }
            }catch(Exception $e){
                echo "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n";
            }
        }
    }
?>