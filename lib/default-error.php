<?php // Copyright (c) 2024, Switch ?>

<!-- Error Message: Start-->
<h1><?php echo getLocalString('invalid_query') ?></h1>
<p>
    <?php echo $message ?>
</p>
<p>
    <?php echo sprintf(getLocalString('contact_assistance'), $supportContactEmail, $supportContactEmail) ?>
</p>
<!-- Error Message: End-->
